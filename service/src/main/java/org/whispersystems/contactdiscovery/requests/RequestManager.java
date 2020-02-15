/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.whispersystems.contactdiscovery.requests;

import com.codahale.metrics.Histogram;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import io.dropwizard.lifecycle.Managed;
import net.openhft.affinity.Affinity;
import net.openhft.affinity.AffinityLock;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.contactdiscovery.directory.DirectoryManager;
import org.whispersystems.contactdiscovery.directory.DirectoryUnavailableException;
import org.whispersystems.contactdiscovery.enclave.NoSuchEnclaveException;
import org.whispersystems.contactdiscovery.enclave.SgxEnclave;
import org.whispersystems.contactdiscovery.enclave.SgxEnclaveManager;
import org.whispersystems.contactdiscovery.enclave.SgxException;
import org.whispersystems.contactdiscovery.enclave.SgxsdMessage;
import org.whispersystems.contactdiscovery.entities.DiscoveryRequest;
import org.whispersystems.contactdiscovery.entities.DiscoveryResponse;
import org.whispersystems.contactdiscovery.util.Constants;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static com.codahale.metrics.MetricRegistry.name;

/**
 * Starts and manages worker threads that drain the pending request queue set
 * and execute the work in its corresponding SGX enclave
 *
 * @author Moxie Marlinspike
 */
public class RequestManager implements Managed {

  private final Logger logger = LoggerFactory.getLogger(RequestManager.class);

  private static final MetricRegistry metricRegistry        = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private static final Meter          processedNumbersMeter = metricRegistry.meter(name(RequestManager.class, "processedNumbers"));
  private static final Timer          processBatchTimer     = metricRegistry.timer(name(RequestManager.class, "processBatch"));
  private static final Histogram      batchSizeHistogram    = metricRegistry.histogram(name(RequestManager.class, "batchSize"));

  private final DirectoryManager       directoryManager;
  private final PendingRequestQueueSet pending;
  private final int                    targetBatchSize;

  public RequestManager(DirectoryManager directoryManager, SgxEnclaveManager enclaveManager, int targetBatchSize) {
    Map<String, PendingRequestQueue> queueMap = new HashMap<>();

    for (Map.Entry<String, SgxEnclave> entry : enclaveManager.getEnclaves().entrySet()) {
      queueMap.put(entry.getKey(), new PendingRequestQueue(entry.getValue()));
    }

    this.directoryManager = directoryManager;
    this.pending          = new PendingRequestQueueSet(queueMap);
    this.targetBatchSize  = targetBatchSize;
  }

  public CompletableFuture<DiscoveryResponse> submit(String enclaveId, DiscoveryRequest request)
      throws NoSuchEnclaveException
  {
    return pending.put(enclaveId, request);
  }

  @Override
  public void start() throws Exception {
    int threadCount = AffinityLock.cpuLayout()
                                  .sockets() *
                      AffinityLock.cpuLayout()
                                  .coresPerSocket();

    for (int i = 0; i< threadCount; i++) {
      new EnclaveThread(directoryManager, i).start();
    }
  }

  @Override
  public void stop() throws Exception {

  }

  private class EnclaveThread extends Thread {

    private final int threadId;
    private final DirectoryManager directoryManager;

    private EnclaveThread(DirectoryManager directoryManager, int threadId) {
      this.directoryManager = directoryManager;
      this.threadId = threadId;
    }

    @Override
    public void run() {
      try (AffinityLock lock = Affinity.acquireCore()) {
        logger.info(this.getClass().getSimpleName() + " on CPU: " + lock.cpuId());

        for (; ; ) {
          Pair<SgxEnclave, List<PendingRequest>> work = pending.get(targetBatchSize);
          SgxEnclave enclave = work.getLeft();
          List<PendingRequest> requests = work.getRight();

          processBatch(enclave, requests);
        }
      }
    }

    private void processBatch(SgxEnclave enclave, List<PendingRequest> requests) {
      Pair<ByteBuffer, Long> registeredUsers;
      try {
        registeredUsers = directoryManager.getAddressList();
      } catch (DirectoryUnavailableException e) {
        logger.warn("Exception getting address list for request batch", e);
        closeRequestsWithException(requests, e);
        return;
      }
      int batchSize = requests.stream().mapToInt(r -> r.getRequest().getAddressCount()).sum();
      try (SgxEnclave.SgxsdBatch batch = enclave.newBatch(threadId, batchSize)) {
        for (PendingRequest request : requests) {
          SgxsdMessage enclaveMessage;
          try {
            enclaveMessage = new SgxsdMessage(request.getRequest().getData(),
                    request.getRequest().getIv(),
                    request.getRequest().getMac(),
                    request.getRequest().getRequestId());
          } catch (IllegalArgumentException e) {
            logger.warn("Null argument passed to SgxdMessage", e);
            closeRequestsWithException(requests, e);
            return;
          }
          try {
            batch.add(enclaveMessage, request.getRequest().getAddressCount())
                    .thenApply(response -> request.getResponse().complete(new DiscoveryResponse(response.getIv(),
                            response.getData(),
                            response.getMac())))
                    .exceptionally(exception -> request.getResponse().completeExceptionally(exception));
          } catch (IllegalArgumentException | IllegalStateException e) {
            logger.warn("Invalid message was being passed to request batch", e);
            closeRequestsWithException(requests, e);
            return;
          }
        }

        processedNumbersMeter.mark(batchSize);
        batchSizeHistogram.update(batchSize);

        try (Timer.Context timer = processBatchTimer.time()) {
          try {
            batch.process(registeredUsers.getLeft(), registeredUsers.getRight());
          } catch (SgxException e) {
            logger.warn("Exception processing request batch", e);
            closeRequestsWithException(requests, e);
            return;
          }
        }
      } catch (SgxException e) {
        logger.warn("Exception creating request batch", e);
        closeRequestsWithException(requests, e);
        return;
      }
    }

    private void closeRequestsWithException(List<PendingRequest> requests, Exception e) {
      requests.stream()
              .map(PendingRequest::getResponse)
              .forEach(future -> future.completeExceptionally(e));
    }
  }
}
