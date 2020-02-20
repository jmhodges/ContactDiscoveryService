package org.whispersystems.contactdiscovery.metrics;


import com.codahale.metrics.Gauge;
import org.whispersystems.contactdiscovery.util.Pair;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public abstract class NetworkGauge implements Gauge<Double> {

  protected Pair<Long, Long> getSentReceived() throws IOException {
    File           proc          = new File("/proc/net/dev");
    // FIXME try-with-resource to close these readers
    BufferedReader reader        = new BufferedReader(new FileReader(proc));
    // FIXME remove these variables and just readLine (or does that flag in spotbugs a different way?)
    String         header        = reader.readLine();
    String         header2       = reader.readLine();

    long           bytesSent     = 0;
    long           bytesReceived = 0;

    String interfaceStats;

      while ((interfaceStats = reader.readLine()) != null) {
        String[] stats = interfaceStats.split("\\s+");

        if (!stats[1].equals("lo:")) {
          bytesReceived += Long.parseLong(stats[2]);
          bytesSent     += Long.parseLong(stats[10]);
        }
      }

    return new Pair<>(bytesSent, bytesReceived);
  }
}
