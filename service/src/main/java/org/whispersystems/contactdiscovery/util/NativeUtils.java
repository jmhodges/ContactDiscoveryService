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

package org.whispersystems.contactdiscovery.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class NativeUtils {

  public static Path extractNativeResource(String resource) throws IOException {
    Path tempFilePath = Files.createTempFile("resource", "so");
    tempFilePath.toFile().deleteOnExit();

    try(OutputStream out = Files.newOutputStream(tempFilePath)) {
      InputStream in = NativeUtils.class.getResourceAsStream(resource);
      if (in == null) {
        throw new IOException("No such resource: " + resource);
      }
      FileUtils.copy(in, out);
    }

    return tempFilePath;
  }

  public static void loadNativeResource(String resource) throws IOException {
    Path extracted = extractNativeResource(resource);
    System.load(extracted.toAbsolutePath().toString());
  }
}
