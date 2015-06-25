Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion21) precise; urgency=low
 .
   * fix __load__.bro
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

--- securityonion-bro-scripts-20121004.orig/__load__.bro
+++ securityonion-bro-scripts-20121004/__load__.bro
@@ -1,6 +1,9 @@
-@load ./sensorname.bro
+@load ./interface
+@load ./sensorname
+@load ./bpfconf
 @load ./add-interface-to-logs
 @load ./load-non-default-scripts
 @load ./conn-add-country
 @load ./conn-add-sensorname
-@load ./bpfconf.bro
+
+@load ./config-bro
