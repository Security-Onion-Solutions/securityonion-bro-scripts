Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion25) precise; urgency=low
 .
   * update sensortab.bro
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

--- securityonion-bro-scripts-20121004.orig/sensortab.bro
+++ securityonion-bro-scripts-20121004/sensortab.bro
@@ -21,12 +21,14 @@ export {
 
 event bro_init()
 	{
-	local peer = get_event_peer()$descr;
-	if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface )
+	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) 
 		{
-		interface = Cluster::nodes[peer]$interface;
-		event SecurityOnion::found_interface(interface);
-		return;
+		local peer = get_event_peer()$descr;
+		if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface )
+			{
+			interface = Cluster::nodes[peer]$interface;
+			event SecurityOnion::found_interface(interface);
+			}
 		}
 	else
 		{
@@ -36,7 +38,7 @@ event bro_init()
 			local lines = split_all(nodefile, /\n/);
 			for ( i in lines )
 				{
-				if ( /^[[:blank:]]*#/ in lines[i])
+				if ( /^[[:blank:]]*#/ in lines[i] )
 					next;
 
 				local fields = split_all(lines[i], /[[:blank:]]*=[[:blank:]]*/);
