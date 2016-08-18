#!/usr/bin/python
"""
This module provides the basic library for accessing the CVMFS catalog. It also
provides various other helper functions for programs.
"""

# Main library version string.
UNCVMFS_VERSION = "0.3"
# The default chunksize to use for downloading file.
UNCVMFS_CHUNKSIZE = 1048576 # 1MiB
# The default number of retries on each server before marking it bad.
UNCVMFS_RETRIES = 3
# The default maximum number of retries on any given file before
# abandoning it. Should probably be > than UNCVMFS_RETRIES
UNCVMFS_MAX_RETRIES = 10

import os
import stat
import time
import zlib
import errno
import Queue
import shutil
import struct
import fnmatch
import hashlib
import httplib
import logging
import sqlite3
import urllib2
import calendar
import tempfile
import threading
import collections
import ConfigParser
# The helper library for signature verification
import CVMFSSig


class CVMFSDownloader(object):
  """ A class for downloading from CVMFS servers.
      This could be a singleton, but why complicate things?
      Unless we decide to do global rate limiting or anything
      like that, it's fine as it is.
  """

  def __init__(self, config):
    """ Create the downloader object.
    """
    self.__config = config

  def __download_core(self, file_fd, url_path, decomp, chunk_size):
    """ The inner loop of the download function.
        Attempts a download from the current base URL.
        Returns the same info as the download function.
    """
    hasher = hashlib.sha1()
    decomp_obj = zlib.decompressobj()
    full_url = "%s%s" % (self.__config.get_current_url(), url_path)
    file_fd.seek(0)
    # Set-up the urllib2 transfer
    proxy_server = self.__config.get_proxy()
    if proxy_server:
      proxy_handler = urllib2.ProxyHandler({'http': self.__config.get_proxy()})
    else:
      proxy_handler = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy_handler)
    url_fd = opener.open(full_url)
    # Transfer the data
    while True:
      data_chunk = url_fd.read(chunk_size)
      if not data_chunk:
        break # Download complete
      hasher.update(data_chunk)
      if decomp:
        data_chunk = decomp_obj.decompress(data_chunk)
      file_fd.write(data_chunk)
    # Ensure everything we wrote is pushed to disk
    file_fd.flush()
    return hasher.hexdigest()

  def download(self, file_fd, url_path, decomp=False, exp_hash=None):
    """ Downloads a remote file into a local fd.
        The source URL will be built from a base_url in config, with url_path
        appended. If decomp is set then the data will be decoded by zlib as it
        is downloaded. Retries sets the number of attempts to try before
        marking a base URL as bad and moving on to the next one.
        If exp_hash is set, the download would be marked as failed if the
        sha1 checksum doesn't match, this is treated the same as any other
        error.
        Note: file_fd is reset to the beginning, so must be seekable.
        Returns: The sha1 hash of the raw (pre-decompression) data.
        Exceptions: Raises an exception on any kind of download error.
                    Errors should be a subclass of IOError
    """
    file_hash = None
    last_err = None
    for retry_num in range(1, self.__config.get_max_retries() + 1):
      try:
        file_hash = self.__download_core(file_fd, url_path,
                                           decomp, UNCVMFS_CHUNKSIZE)
        if exp_hash and (file_hash != exp_hash):
          raise IOError("Checksum failure, Exp %s, Actual %s" % \
                          (exp_hash, file_hash))
        # Everything succesful
        last_err = None
        break
      except IOError as err:
        last_err = str(err)
        if not retry_num % self.__config.get_retries():
          # We've retried enough times that we can switch server now.
          self.__config.bad_url(str(err))
        else:
          cur_server = self.__config.get_current_url()
          bad_url = os.path.join(cur_server, url_path)
          self.__config.get_log().warn("Failed to download %s: %s" % \
                                         (bad_url, str(err)))
    # If we've got here either we have the file, or all requests failed
    if last_err:
      raise IOError("Failed to download file %s (%s)." % (url_path, last_err))
    return file_hash

  def download_string(self, url_path):
    """ Downloads the given URL from a server and return its contents
        as a string. This is primarily designed for small files, like
        the manifest. It is assumed the file is uncompressed and no
        other verification is done.
        Returns: The contents of the downloaded file as a string.
        Exceptions: Raises an exception on any kind of download error.
    """
    # Create a temp file, use the usual download function to grab the remote
    # file, then just re-read and return it.
    tmp_fd = tempfile.TemporaryFile()
    try:
      self.download(tmp_fd, url_path)
    except IOError:
      tmp_fd.close()
      raise
    tmp_fd.seek(0)
    file_data = tmp_fd.read()
    tmp_fd.close()
    return file_data

  def download_hash(self, file_fd, sha1hash, ext=""):
    """ Downloads a file by hash using standard CVMFS server naming.
        This builds a path from sha1hash, optionally adding extension char ext.
        Internally the URL is passed on to the download function, so see that
        for the requirements of file_fd.
        The object is expected to be compressed, as all objects are.
        Returns: None
        Exceptions: Raises an exception on any kind of download error.
    """
    hashp = (sha1hash[0:2], sha1hash[2:])
    path = "/data/%s/%s%s" % (hashp[0], hashp[1], ext)
    self.download(file_fd, path, True, sha1hash)

  def download_cert(self, cert_hash):
    """ Download a certificate and returns the PEM data. This is a cross
        between download_string and download_hash as it downloads a hash,
        but to a string. It also decompresses, unlike download_string.
        Returns: The PEM string.
        Exceptions: Raises an exception on any kind of download error.
    """
    hashp = (cert_hash[0:2], cert_hash[2:])
    path = "/data/%s/%sX" % (hashp[0], hashp[1])
    tmp_fd = tempfile.TemporaryFile()
    try:
      self.download(tmp_fd, path, True, cert_hash)
    except IOError:
      tmp_fd.close()
      raise
    tmp_fd.seek(0)
    cert_data = tmp_fd.read()
    tmp_fd.close()
    return cert_data


class CVMFSManifest(object):
  """ A class for processing CVMFS manifest files.
  """

  def __init__(self, config):
    """ Creates the manifest class but doesn't do anything further.
    """
    self.__config = config
    self.__downloader = CVMFSDownloader(config)
    self.__root_hash = None
    self.__cert_hash = None # The hash of the manifest cert
    self.__raw_manifest = None
    self.__manifest_sig = None

  def download(self):
    """ Downloads the manifest.
        You should also check the signature with verify().
        Returns None on success and an error string on a problem.
    """
    # Clear the previous information
    self.__root_hash = None
    self.__raw_manifest = None
    self.__manifest_sig = None
    # Download the manifest
    self.__config.get_log().debug("Downloading repo manifest...")
    try:
      raw_manifest = self.__downloader.download_string("/.cvmfspublished")
    except IOError as err:
      return "Failed to download manifest: %s" % str(err)
    # Split the body & signature
    manifest_parts = raw_manifest.split("--\n", 1)
    if len(manifest_parts) != 2:
      return "Manifest corrupt: Could not split body & signature"
    self.__raw_manifest, self.__manifest_sig = manifest_parts
    # Now we have the manifest we can split it in to parts
    for line in self.__raw_manifest.split("\n"):
      if len(line) < 2:
        continue # Line too short?
      if line[0] == "C":
        self.__root_hash = line[1:]
        continue
      if line[0] == "X":
        self.__cert_hash = line[1:]
        continue
    # Check we got everything we expect
    if not self.__root_hash or not self.__cert_hash:
      return "Manifest corrupt: Missing root hash"
    self.__config.get_log().debug("Current root hash: %s" % self.__root_hash)
    return None

  @staticmethod
  def __check_sig(method, key, data, sig):
    """ Checks a signature from CVMFS format.
        This checks the hash contained in sig and the binary signature using
        the method function.
        method is a function that takes (key, data, signature) and throws
        an excption if data wasn't signed by key (giving signature). This is
        primarily designed for the CVMFSSig verify_* functions.
        key is given to function as-is.
        data is a plain string containing data to be checked.
        sig is a CVMFS style signature block "sha1_hash\nbinary_signature".
        Returns: None if signature is valid or an error string on problems.
    """
    # The sig hash to parts, expected hash & binary signature
    exp_hash, binary_sig = sig.split("\n", 1)
    # Check the data hash matches the expected hash
    hasher = hashlib.sha1()
    hasher.update(data)
    actual_hash = hasher.hexdigest()
    if actual_hash != exp_hash:
      return "Hash mistmatch"
    try:
      method(key, actual_hash, binary_sig)
    except ValueError as err:
      return err
    except IOError as err:
      return err
    # Looks like this signature is OK
    return None

  @staticmethod
  def __check_whitelist(whitelist, cert_fp):
    """ Checks a certificate fingerprint is on a given whitelist and that
        the whitelist is still within its valid date range.
        Returns: None on success or an error string if something is wrong.
    """
    valid_hashes = []
    wl_expiry = None
    for wl_line in whitelist.split("\n"):
      if not wl_line:
        continue # Ignore blank lines
      # Only use the first line start with E as expiry,
      # certificate hashes may start with E too.
      if wl_line[0] == 'E' and not wl_expiry:
        wl_expiry = wl_line[1:]
        continue
      if (wl_line[0] in "0123456789ABCDEF") and (len(wl_line) >= 59):
        # This is probably a certifiate line, strip any comment...
        real_wl_line = wl_line.split(" ", 1)[0]
        if len(real_wl_line) == 59:
          valid_hashes.append(real_wl_line)
          continue
    # Check the whitelist isn't expired
    if not wl_expiry:
      return "Failed to get whitelist expiry time"
    raw_exp_time = time.strptime(wl_expiry, "%Y%m%d%H%M%S")
    exp_time = calendar.timegm(raw_exp_time) # Expiry time in UTC (epoch secs)
    now_time = time.time() # Current UTC time (epoch seconds)
    if (exp_time - now_time) <= 0:
      return "Whitelist has expired"
    # Now check the certificate is on the list...
    if not cert_fp in valid_hashes:
      return "Certificate not on whitelist"
    # Cert is fine
    return None

  def fetch_whitelist(self):
    """ Downloads & returns the current whitelist.
        Throws an IOError on any problems.
    """
    try:
      whitelist_raw = self.__downloader.download_string("/.cvmfswhitelist")
    except IOError as err:
      raise IOError("Failed to fetch whitelist: %s" % str(err))
    whitelist_parts = whitelist_raw.split("--\n", 1)
    if len(whitelist_parts) != 2:
      raise IOError("Invalid whitelist found")
    whitelist_body, whitelist_sig = whitelist_parts
    # Check the whitelist was signed by one of the root keys
    whitelist_valid = False
    errs = []
    for key_file in self.__config.get_keys():
      err = self.__check_sig(CVMFSSig.verify_rsa, key_file,
                             whitelist_body, whitelist_sig)
      if err:
        errs.append("'%s: %s'" % (key_file, err))
        continue
      # This key works
      whitelist_valid = True
      break
    if not whitelist_valid:
      # None of the keys worked
      raise IOError("Whitelist validation failed: %s" % ", ".join(errs))
    # All OK so far, return the whitelist body
    return whitelist_body

  def verify(self):
    """ Verifies the catalog signature.
        This involves downloading the manifest cert, the repo whitelist
        and checking the chain of signatures.
        Note: Only plain non-chain X509 signatures are supported.
        Returns None on success or an error string on a problem.
    """
    # Initial sanity checks
    if not (self.__raw_manifest and self.__manifest_sig and self.__cert_hash):
      return "Verification error: Manifest not downloaded or incomplete"
    # First we have to fetch the signing cert
    try:
      cert = self.__downloader.download_cert(self.__cert_hash)
    except IOError as err:
      return "Failed to fetch manifest cert: %s" % str(err)
    # Get the certificate fingerprint
    try:
      cert_fp = CVMFSSig.fingerprint(cert)
    except ValueError as err:
      return "Failed to get manifest cert fingerprint: %s" % err
    try:
      whitelist_body = self.fetch_whitelist()
    except IOError as err:
      return "Failed to get whitelist: %s" % err
    # Now check the manifest cert is on the whitelist...
    err = self.__check_whitelist(whitelist_body, cert_fp)
    if err:
      return "Whitelist problem: %s" % err
    # Finally check the manifest was signed with the cert
    err = self.__check_sig(CVMFSSig.verify_x509, cert,
                           self.__raw_manifest, self.__manifest_sig)
    if err:
      return "Manifest signature invalid: %s" % err
    # Everything OK, return None for success

  def get_hash(self):
    """ Returns the hash of the root catalog.
    """
    return self.__root_hash


class CVMFSCatalog(object):
  """ A single CVMFS catalog database.
  """

  def __init__(self, config, cat_path, cat_hash=None, autocommit=100000):
    """ Create the catalog object.
        Autocommit sets how many updates to accept before automatically
        commiting the internal database.
    """
    self.__config = config
    self.__downloader = CVMFSDownloader(config)
    self.__cat_path = cat_path
    self.__cat_hash = cat_hash
    self.__db_conn = None
    self.__changes = 0 # Number of changes (for tracking autocommit)
    self.__autocommit = autocommit
    self.__done_eval = False # We only want to evaulate the "done" flag once
    self.__is_done = False
    # Open the DB here is the hash is valid
    if cat_hash:
      self.__open_db()

  def __del__(self):
    pass
    #self.__close_db() # We can't close here as deleteion is in any thread!

  def __open_db(self):
    """ Opens the DB of the current specified cat_hash. """
    self.__close_db()
    db_path, _, _ = self.__config.get_paths()
    db_file = os.path.join(db_path, "%s.db" % self.__cat_hash)
    self.__db_conn = sqlite3.connect(db_file)
    self.__db_conn.text_factory = str

  def __close_db(self):
    """ Closes the current DB connection. """
    if self.__db_conn:
      self.commit()
      self.__db_conn.close()
      self.__db_conn = None

  def switch_hash(self, new_hash):
    """ Update the catalog to use the new hash.
        Returns True is the switch went successfully.
    """
    self.__config.get_log().debug("Updating '%s': %s -> %s",
                                  self.__cat_path, self.__cat_hash, new_hash)
    # First we download the new catalog
    db_path, _, _ = self.__config.get_paths()
    db_file = os.path.join(db_path, "%s.db" % new_hash)
    new_fd = open(db_file, "w")
    try:
      self.__downloader.download_hash(new_fd, new_hash, "C")
    except IOError as err:
      self.__config.get_log().error("Failed to switch %s from %s to %s: %s",
                                      self.__cat_path, self.__cat_hash, \
                                      new_hash, str(err))
      return False
    new_fd.close()
    # Open the new DB
    old_hash = self.__cat_hash
    old_db_file = os.path.join(db_path, "%s.db" % old_hash)
    self.__cat_hash = new_hash
    self.__open_db()
    # Make schema changes
    sql = "ALTER TABLE catalog ADD COLUMN seen INT DEFAULT 0"
    self.__db_conn.execute(sql)
    # Commit here so we can always guarantee this column is present even
    # if the following bit fails.
    self.__db_conn.commit()
    # Now we have to merge any old records from the previous DB
    if old_hash:
      # This operation is complex, we need to merge any old seen = 1 records
      # and move any old seen = 1 records that aren't in the new catalog,
      # while switching seen = 2 to indicate a deletion is needed.
      # For efficiency we want to do as much of this in single statements as
      # possible, so we'll ATTACH the old catalog and use SQL rather than
      # switching back and forth to python.
      cur = self.__db_conn.cursor()
      cur.execute("ATTACH DATABASE ? AS old", (old_db_file, ))
      # Update the seen = 1 records
      sql = "UPDATE catalog SET seen = 1 WHERE EXISTS " \
              "(SELECT rowid FROM old.catalog WHERE " \
                "old.catalog.md5path_1 = main.catalog.md5path_1 AND " \
                "old.catalog.md5path_2 = main.catalog.md5path_2 AND " \
                "old.catalog.mtime = main.catalog.mtime AND " \
                "old.catalog.mode = main.catalog.mode AND " \
                "old.catalog.seen = 1)"
      cur.execute(sql)
      # Copy in any files that now need deleting
      sql = "UPDATE old.catalog SET seen = 2 WHERE seen = 1"
      cur.execute(sql)
      # We have to list the columns here otherwise new columns may
      # cause things to break
      sql = "INSERT OR IGNORE INTO main.catalog " \
              "(md5path_1, md5path_2, parent_1, parent_2, " \
              "hardlinks, hash, size, mode, mtime, flags, " \
              "name, symlink, uid, gid, seen) " \
              "SELECT " \
              "md5path_1, md5path_2, parent_1, parent_2, " \
              "hardlinks, hash, size, mode, mtime, flags, " \
              "name, symlink, uid, gid, seen " \
              "FROM old.catalog WHERE seen = 2"
      cur.execute(sql)
      # Commit the changes and tidy up
      cur.execute("DETACH DATABASE old")
      self.__db_conn.commit()
      cur.close()
      os.unlink(old_db_file)
    return True

  def children(self):
    """ Returns nested catalogs of this catalog.
        Note: This function is not recursive.
        Returns: A list of (path, hash) tuples, one for each sub-cat.
    """
    cur = self.__db_conn.cursor()
    cur.execute("SELECT path, sha1 FROM nested_catalogs")
    res = cur.fetchall()
    cur.close()
    return res

  def is_done(self):
    """ Returns true if a catalog is complete, false otherwise.
        A catalog is complete if it has no children and all the
        files are marked as seen (except the root directory which is
        never set as seen).
    """
    if self.__done_eval:
      return self.__is_done
    # Check this catalog has no children
    if self.children():
      self.__is_done = False
      self.__done_eval = True
      return False
    # Check how many files are set as seen:
    cur = self.__db_conn.cursor()
    sql = "SELECT COUNT(rowid) FROM catalog WHERE seen != 1"
    cur.execute(sql)
    res = cur.fetchone()
    cur.close()
    # Check the number of objects left to process
    self.__is_done = (res[0] <= 1)
    self.__done_eval = True
    return self.__is_done

  @staticmethod
  def __hash_path(path):
    """ Calculates the CVMFS hash of this path.
        Returns a tuple, the (md5path_1, md5path_2) parts.
    """
    # The root inode is a special case
    if path == "/":
      real_path = ""
    else:
      real_path = path
    hasher = hashlib.md5()
    hasher.update(real_path)
    raw_hash = hasher.digest()
    # Reverse the hash parts
    # Quite why CVMFS uses reversed-endian hashes I don't know...
    part1 = struct.unpack('>q', raw_hash[7::-1])[0]
    part2 = struct.unpack('>q', raw_hash[16:7:-1])[0]
    return (part1, part2)

  def listdir(self, path):
    """ List a dir.
        This is similar to os.listdir() but returns a lot more information
        about the contained objects in one go.
        path should be a pre-normalised CVMFS path.
        Returns a tuple of lists (dirs, links, files)
        The lists contain further tuples, one for each object:
          dirs -> (name, seen, path_hash)
          links -> (name, target, seen, path_hash)
          files -> (name, size, mode, sha1hash, seen, path_hash)
          path_hash in the above is a (md5path_1, md5path_2) tuple.
        If path does not exist, ([]. []. []) will be returned and no error
        will be generated.
    """
    # Lookup the contents of this path
    dirs = []
    links = []
    files = []
    cur = self.__db_conn.cursor()
    sql = "SELECT name, size, mode, hash, symlink, seen, md5path_1, md5path_2" \
             " FROM catalog WHERE parent_1 = ? AND parent_2 = ? ORDER BY name"
    cur.execute(sql, self.__hash_path(path))
    while True:
      res = cur.fetchone()
      if not res:
        break # All entries iterated
      real_fname, fsize, fmode = res[0:3]
      fsymlink, fseen = res[4:6]
      fmd5path = res[6:8]
      # Replace any special characters in the filename with "?"
      fname_list = []
      for f_chr in real_fname:
        if ord(f_chr) < 32 or ord(f_chr) > 126:
          fname_list.append("?")
        else:
          fname_list.append(f_chr)
      fname = ''.join(fname_list)
      if stat.S_ISDIR(fmode):
        dirs.append((fname, fseen, fmd5path))
      elif stat.S_ISLNK(fmode):
        links.append((fname, fsymlink, fseen, fmd5path))
      elif stat.S_ISREG(fmode):
        # Get the file hash into a string value
        fhash = ''.join('%02x' % ord(byte) for byte in res[3])
        files.append((fname, fsize, fmode, fhash, fseen, fmd5path))
      # Any files types that don't match the above get ignored.
    cur.close()
    return (dirs, links, files)

  def set_seen(self, path_hash, seen=1):
    """ Set the seen state of a given file in the DB.
        path_hash should be a tuple: (md5path_1, md5path_2).
        This is primarily designed to mark files as downloaded but any,
        even invalid, values for seen will be accepted.
        Note: This function does not commit the DB.
    """
    sql = "UPDATE catalog SET seen = ? WHERE md5path_1 = ? AND md5path_2 = ?"
    self.__db_conn.execute(sql, (seen, path_hash[0], path_hash[1]))
    self.__changes += 1
    if not self.__changes % 1000:
      self.__config.get_log().debug("Processed %d changes.", self.__changes)
    if self.__autocommit and (not self.__changes % self.__autocommit):
      self.commit()

  def deleted(self, path_hash):
    """ Completed remove a file from the database.
        path_hash should be a tuple: (md5path_1, md5path_2).
        Note: This function does not commit the DB.
    """
    sql = "DELETE FROM catalog WHERE md5path_1 = ? AND md5path_2 = ?"
    self.__db_conn.execute(sql, path_hash)
    self.__changes += 1
    if self.__autocommit and (not self.__changes % self.__autocommit):
      self.commit()

  def commit(self):
    """ Commit the internal database to disk. """
    self.__db_conn.commit()
    if self.__changes:
      self.__config.get_log().debug("Commit on %d changes.", self.__changes)

  def walk(self, path, skip_done=False):
    """ Walk the CVMFS filesystem.
        This generator provides an os.walk() style interface to CVMFS.
        The path given should be an absolute path within the filesystem.
        The skip_done flag causes catalogs which require no changes (and have
        no children) to be skipped.
        The returned tuples have the format:
          (catalog, step, dirs, links, files)
        catalog is a reference to the CVMFSCatalog object containing these
        entries, to allow for ease of access to the stored & deleted fcns.
        The tuples are returned twice for each directory, the first time
        step=0 and this is before the sub-dirs have been recursed. The second
        time step=1 after the sub-dirs have been recursed. This duality allows
        for creations & deletions to be processed in one walk of the tree.
        A third step=2 is generated when the catalog is finished, this allows
        for the catalog to be committed once any pending downloads are done.
        The dirs, links and files values are lists of tuples in the forms:
          dirs -> (name, seen, path_hash)
          links -> (name, target, seen, path_hash)
          files -> (name, size, mode, sha1hash, seen, path_hash)
          path_hash in the above is a (md5path_1, md5path_2) tuple.
        The "seen" value in the above has the standard unCVMFS,
          seen=0 for objects not yet created on disk, seen=1 for resident
          objects and seen=2 for for objects pending deletion.
        Removing an dir from the dirs list when step=0 will prevent it from
        being travesed (step=1 will return the updated dirs list, not the
        original).
        Note: If input path doesn't exist, no error will be returned, the
              function will just exit without yielding.
    """
    real_path = os.path.normpath(path)
    # Check if this catalog is already complete...
    if skip_done and self.is_done():
      return
    # We keep a list of sub catalogs ready for doing recusion later...
    sub_cats = {}
    for cat_path, cat_hash in self.children():
      sub_cats[cat_path] = cat_hash
    # We'll do a quick sanity check before getting started
    if not self.__cat_path in real_path:
      raise ValueError("Walk path '%s' not in this catalog ('%s')" % \
                         (real_path, self.__cat_path))
    # Enumerate the dir
    dirs, links, files = self.listdir(real_path)
    yield (self, 0, real_path, dirs, links, files)
    # Handle the recursion
    for dir_name, _, _ in dirs:
      dir_path = os.path.join(real_path, dir_name)
      if dir_path in sub_cats:
        # This dir is a mountpoint, traverse down
        self.__config.get_log().debug("Walking into '%s'..." % dir_path)
        cat_obj = CVMFSCatalog(self.__config, dir_path, sub_cats[dir_path])
        for sub_info in cat_obj.walk(dir_path, skip_done):
          yield sub_info
        yield (cat_obj, 2, real_path, [], [], [])
      else:
        # This is a plain dir
        for sub_info in self.walk(dir_path, skip_done):
          yield sub_info
    yield (self, 1, real_path, dirs, links, files)


class CVMFSManager(object):
  """ A full CVMFS repo manager consisting of one of more catalogs.
  """

  def __init__(self, config):
    """ Create a CVMFSManager object.
        config: A config object.
    """
    self.__config = config
    self.__db_conn = None
    # Open the database
    db_path, _, _ = config.get_paths()
    db_file = os.path.join(db_path, "catalogs.db")
    self.__db_conn = sqlite3.connect(db_file)
    self.__db_conn.text_factory = str
    # Create the DB if needed
    sql = "CREATE TABLE IF NOT EXISTS catalogs " \
            "(path TEXT PRIMARY KEY, hash TEXT, seen INT)"
    self.__db_conn.execute(sql)
    self.__db_conn.commit()
    self.__whitelist_paths = config.get_whitelist()
    self.__blacklist_paths = config.get_blacklist()

  def __del__(self):
    if self.__db_conn:
      self.__db_conn.close()
      self.__db_conn = None

  def __valid_path(self, pathname):
    for entry in self.__blacklist_paths:
      if fnmatch.fnmatch(pathname, entry):
        return False
    if self.__whitelist_paths:
      for entry in self.__whitelist_paths:
        if fnmatch.fnmatch(pathname, entry):
          return True
      return False
    return True

  def __cat_hash(self, cat_path):
    """ Gets the current known hash for a given path.
        Returns the hash string or none.
    """
    cur_hash = None
    cur = self.__db_conn.cursor()
    sql = "SELECT hash FROM catalogs WHERE path = ?"
    cur.execute(sql, (cat_path,))
    res = cur.fetchone()
    cur.close()
    if res:
      cur_hash = res[0]
    return cur_hash

  def mountpoints(self):
    """ Returns a dictionary of all catalogs:
        { 'path1': hash1, 'path2': hash2, ... }
    """
    cur = self.__db_conn.cursor()
    sql = "SELECT path, hash FROM catalogs"
    cur.execute(sql)
    res = cur.fetchall()
    cur.close()
    # Now convert it to a dictionary
    cats = {}
    for cat_path, cat_hash in res:
      cats[cat_path] = cat_hash
    return cats

  def __update_cats(self, cat_path, cat_hash):
    """ Updates the given catalog and then recursively updates
        all sub-catalogs.
        Returns: a tuple of ints (total num catalogs, updated catalogs)
    """
    # Get the old hash of the catalog
    num_total = 1
    num_updated = 0
    old_hash = self.__cat_hash(cat_path)
    cat_obj = CVMFSCatalog(self.__config, cat_path, old_hash)
    # If the hash has changed, update the catalog
    if old_hash != cat_hash:
      cat_obj.switch_hash(cat_hash)
      num_updated += 1
    else:
      self.__config.get_log().debug("Not Updating '%s'.", cat_path)
    # Update our DB
    sql = "INSERT OR REPLACE INTO catalogs " \
          "(path, hash, seen) VALUES (?, ?, 1)"
    self.__db_conn.execute(sql, (cat_path, cat_hash))
    self.__db_conn.commit() # Ensure DB is now consistent
    # Now process the sub-catalogs
    for sub_path, sub_hash in cat_obj.children():
      # Skip blacklisted sub-catalogs
      for entry in self.__blacklist_paths:
        if fnmatch.fnmatch(sub_path, entry):
          continue
      sub_total, sub_updated = self.__update_cats(sub_path, sub_hash)
      num_total += sub_total
      num_updated += sub_updated
    # Return the stats
    return (num_total, num_updated)

  def update(self):
    """ Updates the catalogs from the server.
        Returns stats as tuple of ints (total cats, updated cats).
        Raises an exception on an error (normally IOError).
    """
    # Get the current root hash from the manifest
    manifest = CVMFSManifest(self.__config)
    err = manifest.download()
    if err:
      raise IOError("Failed to download manifest: %s" % err)
    err = manifest.verify()
    if err:
      raise IOError("Manifest verification failed: %s" % err)
    # Start off by marking everything as unseen so far
    self.__db_conn.execute("UPDATE catalogs SET seen = 0")
    self.__db_conn.commit()
    # Now we can actually do the update
    res = self.__update_cats("/", manifest.get_hash())
    # TODO: Remove any unused catalogs here
    return res

  def walk(self, path, skip_done=False):
    """ Walk the CVMFS file system.
        This is mainly a short wrapper around CVMFSCatalog.walk(),
        see the documentation of that for further details; the return
        semantics are maintained by this function.
    """
    real_path = os.path.normpath(path)
    # First, find the best catalog for the given path
    # The "best catalog" is the one with the longest path which
    # still matches the user defined path
    best_cat = ""
    cats = self.mountpoints()
    for cat_path in cats:
      if real_path.startswith(cat_path) and \
           len(cat_path) > len(best_cat):
        best_cat = cat_path
    if not best_cat:
      raise ValueError("No catalog found, root catalog missing?")
    # We now have the best cat, walk it!
    cat_obj = CVMFSCatalog(self.__config, best_cat, cats[best_cat])
    for info in cat_obj.walk(real_path, skip_done):
      if self.__valid_path(info[2]):
        yield info
    # Complete the final catalog
    yield (cat_obj, 2, real_path, [], [], [])


class UNCVMFSDownloadPool(object):
  """ An UNCVMFS thread pool for downloading files.
      This handles the starting, running & stopping of download threads.
  """

  def __init__(self, config, num_threads):
    """ Create a thread pool with num_threads threads. """
    self.__config = config
    self.__downloadq = Queue.Queue(num_threads * 4)
    self.__doneq = Queue.Queue()
    self.__finished = threading.Event() # A flag for quitting threads.
    self.__processing = [] # A list of hashes currently being processed.
    self.__lock = threading.Condition() # A lock on the processing list
    self.__threads = []
    #  Start the threads
    for _ in range(0, num_threads):
      new_thread = threading.Thread(target=self.__thread_core)
      new_thread.daemon = True
      new_thread.start()
      self.__threads.append(new_thread)

  def __del__(self):
    """ Just calls shutdown(). """
    self.shutdown()

  def shutdown(self):
    """ Shutdown all threads.
        This can take up to 2 seconds to wait for the threads to stop.
        Note: This dumps the remaining doneq.
              wait() & completed() should have been called until all the
              processing was complete before the object is shutdown.
    """
    self.__finished.set()
    for thread in self.__threads:
      thread.join()

  def __lock_hash(self, fhash):
    """ This function waits until no other thread is processing fhash.
        Used for synchronisation of multiple threads which may try to download
        the same file at the same time.
    """
    self.__lock.acquire()
    while fhash in self.__processing:
      self.__lock.wait()
    self.__processing.append(fhash)
    self.__lock.release()

  def __unlock_hash(self, fhash):
    """ Marks a given file hash as no-longer in use by a thread.
        This will unlock the next thread waiting for it in __lock_hash if
        there is one...
    """
    self.__lock.acquire()
    self.__processing.remove(fhash)
    self.__lock.notifyAll()
    self.__lock.release()

  def __thread_core(self):
    """ The inner loop for processing downloads. """
    downloader = CVMFSDownloader(self.__config)
    _, _, store_path = self.__config.get_paths()
    # Start the main thread loop
    try:
      while not self.__finished.is_set():
        try:
          cat_obj, path, file_info = self.__downloadq.get(True, 2)
        except Queue.Empty:
          continue # No work currently...
        # Mark the file hash as being processed
        fhash = file_info[3]
        self.__lock_hash(fhash)
        # Handle the store_path object (i.e. the download)
        hash_path = os.path.join(store_path, fhash[0:2], fhash[2:])
        if not os.path.exists(hash_path):
          file_fd = open(hash_path, "w")
          try:
            downloader.download_hash(file_fd, fhash)
          except IOError as err:
            file_fd.close()
            self.__unlock_hash(fhash)
            self.__doneq.put(("Failed to download (%s): %s" % (hash_path, err),
                               cat_obj, file_info))
            self.__downloadq.task_done()
            continue
          except httplib.BadStatusLine as err:
            file_fd.close()
            self.__unlock_hash(fhash)
            self.__doneq.put(("Server error, BSL (%s): %s" % (hash_path, err),
                               cat_obj, file_info))
            self.__downloadq.task_done()
            continue
          # Set the permissions on the new file
          # We don't support the full permissions model, just +x or not!
          if file_info[2] & stat.S_IXUSR: # file_info[2] is fmode
            os.fchmod(file_fd.fileno(), 0755)
          else:
            os.fchmod(file_fd.fileno(), 0644)
          file_fd.close()
        else:
          # The file already exists, but we may need to make it executable
          # This works around if the file has different permissions in two
          # different places by making +x additive
          if file_info[2] & stat.S_IXUSR:
            os.chmod(hash_path, 0755)
        # Check the file is the size we expect
        if os.path.getsize(hash_path) != file_info[1]: # file_info[1] is fsize
          os.unlink(hash_path)
          self.__unlock_hash(fhash)
          self.__doneq.put(("File size mismatch (%s)." % hash_path,
                              cat_obj, file_info))
          self.__downloadq.task_done()
          continue
        self.__unlock_hash(fhash)
        # Now handle creating the data_path object
        file_path = os.path.join(path, file_info[0])
        try:
          os.link(hash_path, file_path)
        except OSError as err:
          if err.errno == errno.EMLINK:
            # Too many hard links to this file, we have to copy it instead...
            shutil.copy2(hash_path, file_path)
          else:
            # Some kind of genuine error
            self.__doneq.put(("Failed to link (%s, %s): %s" % \
                                (hash_path, file_path, err),
                                 cat_obj, file_info))
            self.__downloadq.task_done()
            continue
        # All done
        self.__doneq.put((None, cat_obj, file_info))
        self.__downloadq.task_done()
    # Catch all errors
    except Exception:
      self.__config.get_log().exception("[BUG] Thread failed")

  def download(self, cat_obj, path, file_info):
    """ Add a file onto the download queue, with the given
        properties. With target (on-disk) path "path".
        file_info is a file tuple as returned by the listdir
        function in CVMFSCatalog.listdir() & walk():
          (name, size, mode, sha1hash, seen, path_hash)
        Returns nothing.
    """
    self.__downloadq.put((cat_obj, path, file_info))

  def completed(self):
    """ Deal with the next item on the completed queue.
        Returns an empty string on success, an error string on
        error. Returns None is there was no next item on the queue.
    """
    try:
      err, cat_obj, file_info = self.__doneq.get(False)
      self.__doneq.task_done()
      if err:
        return err
      path_hash = file_info[5]
      cat_obj.set_seen(path_hash)
      return ""
    except Queue.Empty:
      return None

  def wait(self):
    """ Wait until the download queue is finished.
    """
    self.__downloadq.join()


class UNCVMFSConfig(object):
  """ An UNCVMFS config object.
      Mainly holds the data from the config file.
  """

  def __init__(self):
    """ Create an empty config class. """
    self.__log = logging.getLogger("UNCVMFSLib")
    self.__db_path = None
    self.__data_path = None
    self.__store_path = None
    self.__proxy = ""
    self.__urls = None
    self.__keys = None
    self.__whitelist_paths = []
    self.__blacklist_paths = []
    self.__env = {}

  def load_config(self, filename, repo):
    """ Loads the config from filename, using specific repo section.
        Returns None if everything is OK, or an error string if there
        was a problem with the config.
    """
    def get_array_opt(opt_str):
      """ A function to take a ; seperate string and return a list. """
      # Return a list of non-empty strings.
      return [x.strip() for x in opt_str.split(";") if x.strip()]

    # First read the file
    conf = ConfigParser.ConfigParser()
    conf.read(filename)
    for opt in conf.options(repo):
      if opt == 'db_path':
        tmp_path = conf.get(repo, "db_path")
        self.__db_path = os.path.normpath(tmp_path)
      elif opt == 'data_path':
        tmp_path = conf.get(repo, "data_path")
        self.__data_path = os.path.normpath(tmp_path)
      elif opt == 'store_path':
        tmp_path = conf.get(repo, "store_path")
        self.__store_path = os.path.normpath(tmp_path)
      elif opt == 'urls':
        tmp_urls = get_array_opt(conf.get(repo, "urls"))
        self.__urls = collections.deque(tmp_urls)
      elif opt == 'keys':
        self.__keys = get_array_opt(conf.get(repo, "keys"))
      elif opt == 'blacklist_paths':
        self.__blacklist_paths = get_array_opt(conf.get(repo, "blacklist_paths"))
      elif opt == 'whitelist_paths':
        self.__whitelist_paths = get_array_opt(conf.get(repo, "whitelist_paths"))
      elif opt == 'proxy':
        self.__proxy = conf.get(repo, "proxy")
      elif opt == 'env':
        # Split each env var into key, value for the dict
        for var in get_array_opt(conf.get(repo, "env")):
          var_split = var.split("=")
          if len(var_split) != 2:
            return "Invalid env entry: %s" % var
          self.__env[var_split[0]] = var_split[1]
      else:
        return "Unknown config parameter: %s" % opt
    # Check all the values were correctly read
    for val_name, val in (("db_path", self.__db_path),
                          ("data_path", self.__data_path),
                          ("store_path", self.__store_path),
                          ("urls", self.__urls),
                          ("keys", self.__keys)):
      if not val:
        return "%s missing from config file." % val_name

  def create_paths(self):
    """ Attempts to create the paths used by UNCVMFS.
    """
    def __mkdir(path):
      """ A helper mkdir function like mkdir -p """
      if os.path.exists(path):
        return
      head, _ = os.path.split(path)
      if not os.path.exists(head):
        __mkdir(head)
      os.mkdir(path)

    db_path, data_path, store_path = self.get_paths()
    paths = [os.path.join(store_path, "%02x" % x) for x in range(0, 256)]
    paths.append(db_path)
    paths.append(data_path)
    for path in paths:
      __mkdir(path)

  def get_blacklist(self):
    """ Returns a list of Unix globs representing a blacklist
        for this repo.  Any path matching these globs should not
        be synchronized.
    """
    return self.__blacklist_paths

  def get_whitelist(self):
    """ Return a list of Unix globs representing a whitelist for
        this repo.  If non-empty, then all synchronized paths should
        match at least one glob on the whitelist.
    """
    return self.__whitelist_paths

  def get_log(self):
    """ Returns a logging object for the UNCVMFS Library.
    """
    return self.__log

  def get_paths(self):
    """ Returns a tuple of paths from the config in the order:
        (db_path, data_path, store_path)
    """
    return (self.__db_path, self.__data_path, self.__store_path)

  def get_proxy(self):
    """ Returns the proxy server the user specified. """
    return self.__proxy

  def get_urls(self):
    """ Returns a list of repo URLs from the config. """
    return list(self.__urls)

  def get_current_url(self):
    """ Returns the next URL. """
    return self.__urls[0]

  def bad_url(self, reason):
    """ Marks the current URL as bad (moving on to the next one).
        Reason is logged in the log so the user knows there is a problem.
    """
    self.__log.warn("Bad Base URL '%s': %s", self.__urls[0], reason)
    self.__urls.rotate(-1)
    self.__log.warn("New Base URL '%s'.", self.__urls[0])

  def get_keys(self):
    """ Returns a list of key filenames from config. """
    return self.__keys

  def expand_env(self, target):
    """ Returns target but with any environment variables expanded using the
        information from the config file
    """
    # Temporarily replace the environment
    env = os.environ
    os.environ = self.__env
    real_target = target
    # Replace any $(VARS) with ${VARS}
    if "$(" in real_target:
      head, tail = real_target.split("$(")
      tail = tail.replace(")", "}", 1)
      real_target = "%s${%s" % (head, tail)
    # Now do the expansion
    real_target = os.path.expandvars(real_target)
    os.environ = env
    return real_target

  @staticmethod
  def get_retries():
    """ The number of retries for each base URL before switching. """
    return UNCVMFS_RETRIES

  @staticmethod
  def get_max_retries():
    """ The maximum number of retries for any given file. """
    return UNCVMFS_MAX_RETRIES

