Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion26) precise; urgency=low
 .
   * update bpfconf.bro
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

--- securityonion-bro-scripts-20121004.orig/bpfconf.bro
+++ securityonion-bro-scripts-20121004/bpfconf.bro
@@ -75,11 +75,10 @@ function add_filter_file()
 
 	if ( /\{\{/ in real_filter_filename )
 		{
-		Reporter::warning(fmt("Template value remaining in BPFConf filename: %s", real_filter_filename));
 		return;
 		}
 	else
-		Reporter::info(fmt("BPFConf filename set: %s", real_filter_filename));
+		Reporter::info(fmt("BPFConf filename set: %s (%s)", real_filter_filename, Cluster::node));
 
 	if ( real_filter_filename != current_filter_filename )
 		{
@@ -98,10 +97,6 @@ event SecurityOnion::found_sensorname(na
 	{
 	add_filter_file();
 	}
-event SecurityOnion::found_interface(inter: string)
-	{
-	add_filter_file();
-	}
 
 event bro_init() &priority=5
 	{
--- securityonion-bro-scripts-20121004.orig/sensortab.bro
+++ securityonion-bro-scripts-20121004/sensortab.bro
@@ -17,23 +17,26 @@ export {
 
 	## Name of the sensor.
 	global sensorname = "";
+
+	## The filename where the sensortab is located.
+	const sensortab_file = "/opt/bro/etc/node.cfg" &redef;
 }
 
 event bro_init()
 	{
 	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER ) 
 		{
-		local peer = get_event_peer()$descr;
-		if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface )
+		local node = Cluster::node;
+		if ( node in Cluster::nodes && Cluster::nodes[node]?$interface )
 			{
-			interface = Cluster::nodes[peer]$interface;
+			interface = Cluster::nodes[node]$interface;
 			event SecurityOnion::found_interface(interface);
 			}
 		}
-	else
+	else if ( Cluster::local_node_type() != Cluster::MANAGER ) 
 		{
 		# If running in standalone mode...
-		when ( local nodefile = readfile("/opt/bro/etc/node.cfg") )
+		when ( local nodefile = readfile(sensortab_file) )
 			{
 			local lines = split_all(nodefile, /\n/);
 			for ( i in lines )
@@ -74,4 +77,4 @@ event SecurityOnion::found_interface(int
 				}
 			}
 		}
-	}
\ No newline at end of file
+	}
