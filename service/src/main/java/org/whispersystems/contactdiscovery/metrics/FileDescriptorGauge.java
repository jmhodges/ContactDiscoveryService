package org.whispersystems.contactdiscovery.metrics;


import com.codahale.metrics.Gauge;

import java.io.File;

public class FileDescriptorGauge implements Gauge<Integer> {
  @Override
  public Integer getValue() {
    File file = new File("/proc/self/fd");

    if (file.isDirectory() && file.exists()) {
      // FIXME We could probably solve this (mostly spurious) null dereference problem with Files.list or similar.
      return file.list().length;
    }

    return 0;
  }
}
