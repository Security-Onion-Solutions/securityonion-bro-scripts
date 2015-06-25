Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion19) precise; urgency=low
 .
   * fix typo in __load__.bro
Author: Doug Burks <doug.burks@gmail.com>

---
The information above should follow the Patch Tagging Guidelines, please
checkout http://dep.debian.net/deps/dep3/ to learn about the format. Here
are templates for supplementary fields that you might want to add:

Origin: <vendor|upstream|other>, <url of original patch>
Bug: <url in upstream bugtracker>
Bug-Debian: http://bugs.debian.org/<bugnumber>
Bug-Ubuntu: https://launchpad.net/bugs/<bugnumber>
Forwarded: <no|not-needed|url proving that it has been forwarded>
Reviewed-By: <name and email of someone who approved the patch>
Last-Update: <YYYY-MM-DD>

--- securityonion-bro-scripts-20121004.orig/apt1/__load__.bro
+++ securityonion-bro-scripts-20121004/apt1/__load__.bro
@@ -4,6 +4,6 @@
 
 redef Intel::read_files += {
   fmt("%s/apt1-fqdn.dat", @DIR),
-  fmt("%s/apt1-md5.dat", @DIR)
+  fmt("%s/apt1-md5.dat", @DIR),
   fmt("%s/apt1-certs.dat", @DIR)
 };
