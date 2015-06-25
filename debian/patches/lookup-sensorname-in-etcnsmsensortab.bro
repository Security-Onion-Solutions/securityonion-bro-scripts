Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion20) precise; urgency=low
 .
   * lookup sensorname in /etc/nsm/sensortab.bro
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
@@ -3,16 +3,16 @@
 ##! hacks in it to work around bugs discovered in Bro.
 
 @load base/frameworks/notice
-@load ./hostname
 @load ./interface
+@load ./sensorname
 
 module BPFConf;
 
 export {
 	## The file that is watched on disk for BPF filter changes.
-	## Two templated variables are available; "hostname" and "interface".
-	## They can be used by surrounding the term by doubled curly braces.
-	const filename = "/etc/nsm/{{hostname}}-{{interface}}/bpf-bro.conf" &redef;
+	## A templated variable is available: "sensorname".
+	## It can be used by surrounding the term by doubled curly braces.
+	const filename = "/etc/nsm/{{sensorname}}/bpf-bro.conf" &redef;
 
 	redef enum Notice::Type += { 
 		## Invalid filter notice.
@@ -86,13 +86,12 @@ function add_filter_file()
 	{
 	local real_filter_filename = BPFConf::filename;
 
-	# Support the interface template value.
-	if ( SecurityOnion::interface != "" )
-		real_filter_filename = gsub(real_filter_filename, /\{\{interface\}\}/, SecurityOnion::interface);
-	
-	# Support the hostname template value.
-	if ( SecurityOnion::hostname != "" )
-		real_filter_filename = gsub(real_filter_filename, /\{\{hostname\}\}/, SecurityOnion::hostname);
+	# Support the sensorname template value.
+	if ( SecurityOnion::interface in SecurityOnion::sensornames)
+		{
+		if ( SecurityOnion::sensornames[SecurityOnion::interface]$sensorname != "" )
+			real_filter_filename = gsub(real_filter_filename, /\{\{sensorname\}\}/, SecurityOnion::sensornames[SecurityOnion::interface]$sensorname);
+		}
 
 	if ( /\{\{/ in real_filter_filename )
 		{
@@ -115,17 +114,7 @@ function add_filter_file()
 		}
 	}
 
-event SecurityOnion::found_hostname(hostname: string)
+event Input::end_of_data(name: string, source: string) 
 	{
 	add_filter_file();
 	}
-event SecurityOnion::found_interface(inter: string)
-	{
-	add_filter_file();
-	}
-
-event bro_init() &priority=5
-	{
-	if ( BPFConf::filename != "" )
-		add_filter_file();
-	}
--- securityonion-bro-scripts-20121004.orig/__load__.bro
+++ securityonion-bro-scripts-20121004/__load__.bro
@@ -1,9 +1,6 @@
-@load ./hostname
-@load ./interface
-@load ./bpfconf
+@load ./sensorname.bro
 @load ./add-interface-to-logs
 @load ./load-non-default-scripts
 @load ./conn-add-country
 @load ./conn-add-sensorname
-
-@load ./config-bro
+@load ./bpfconf.bro
--- /dev/null
+++ securityonion-bro-scripts-20121004/sensorname.bro
@@ -0,0 +1,26 @@
+module SecurityOnion;
+
+@load ./interface
+@load base/frameworks/input
+
+export {
+
+    global sensorname = "";
+
+	type Idx: record {
+	        interface: string;
+	};
+
+	type Val: record {
+        	sensorname: string;
+	};
+
+	global sensornames: table[string] of Val = table();
+
+}
+
+event bro_init() &priority=5
+    {
+	Input::add_table([$source="/etc/nsm/sensortab.bro", $name="sensornames", $idx=Idx, $val=Val, $destination=sensornames]);
+	Input::remove("sensornames");
+    }   
--- securityonion-bro-scripts-20121004.orig/conn-add-sensorname.bro
+++ securityonion-bro-scripts-20121004/conn-add-sensorname.bro
@@ -1,5 +1,5 @@
-@load ./hostname
 @load ./interface
+@load ./sensorname
 
 redef record Conn::Info += {
         sensorname: string &log &optional;
@@ -7,7 +7,9 @@ redef record Conn::Info += {
 
 event connection_state_remove(c: connection)
         {
-local sensorname = cat(SecurityOnion::hostname, "-", SecurityOnion::interface);
-                c$conn$sensorname = sensorname;
+		if ( SecurityOnion::interface in SecurityOnion::sensornames)
+			{
+	                c$conn$sensorname = SecurityOnion::sensornames[SecurityOnion::interface]$sensorname;
+			}
         }
 
