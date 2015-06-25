Description: <short summary of the patch>
 TODO: Put a short summary on the line above and replace this paragraph
 with a longer explanation of this change. Complete the meta-information
 with other relevant fields (see below for details). To make it easier, the
 information below has been extracted from the changelog. Adjust it or drop
 it.
 .
 securityonion-bro-scripts (20121004-0ubuntu0securityonion7) precise; urgency=low
 .
   * update hostname.bro and interface.bro
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

--- securityonion-bro-scripts-20121004.orig/interface.bro
+++ securityonion-bro-scripts-20121004/interface.bro
@@ -19,21 +19,10 @@ event SecurityOnion::interface_line(desc
 	if ( 3 in parts )
 		{
 		interface = parts[3];
-		system(fmt("rm %s", description$source));
 		event SecurityOnion::found_interface(interface);
 		}
 	}
 
-event add_interface_reader(name: string)
-	{
-	Input::add_event([$source=name,
-	                  $name=name,
-	                  $reader=Input::READER_RAW,
-	                  $want_record=F,
-	                  $fields=InterfaceCmdLine,
-	                  $ev=SecurityOnion::interface_line]);
-	}
-
 event bro_init() &priority=5
 	{
 	local peer = get_event_peer()$descr;
@@ -45,8 +34,12 @@ event bro_init() &priority=5
 		}
 	else
 		{
-		local tmpfile = "/tmp/bro-interface-" + unique_id("");
-		system(fmt("grep \"interface\" /opt/bro/etc/node.cfg 2>/dev/null | grep -v \"^[[:blank:]]*#\" > %s", tmpfile));
-		event add_interface_reader(tmpfile);
+		Input::add_event([$source= "grep \"interface\" /opt/bro/etc/node.cfg 2>/dev/null | grep -v \"^[[:blank:]]*#\" |",
+				$name="SO-interface",
+				$reader=Input::READER_RAW,
+				$want_record=F,
+				$fields=InterfaceCmdLine,
+				$ev=SecurityOnion::interface_line]);		
 		}
 	}
+
--- securityonion-bro-scripts-20121004.orig/hostname.bro
+++ securityonion-bro-scripts-20121004/hostname.bro
@@ -3,35 +3,28 @@ module SecurityOnion;
 @load base/frameworks/input
 
 export {
-	## Event to capture when the hostname is discovered.
-	global SecurityOnion::found_hostname: event(hostname: string);
+    ## Event to capture when the hostname is discovered.
+    global SecurityOnion::found_hostname: event(hostname: string);
 
-	## Hostname for this box.
-	global hostname = "";
-}
+    ## Hostname for this box.
+    global hostname = "";
 
-type HostnameCmdLine: record { s: string; };
+    type HostnameCmdLine: record { s: string; };
+}
 
 event SecurityOnion::hostname_line(description: Input::EventDescription, tpe: Input::Event, s: string)
-	{
-	hostname = s;
-	system(fmt("rm %s", description$source));
-	event SecurityOnion::found_hostname(hostname);
-	}
-
-event add_hostname_reader(name: string)
-	{
-	Input::add_event([$source=name,
-	                  $name=name,
-	                  $reader=Input::READER_RAW,
-	                  $want_record=F,
-	                  $fields=HostnameCmdLine,
-	                  $ev=SecurityOnion::hostname_line]);
-	}
+    {
+    hostname = s;
+    event SecurityOnion::found_hostname(hostname);
+    Input::remove(description$name);
+    }   
 
 event bro_init() &priority=5
-	{
-	local tmpfile = "/tmp/bro-hostname-" + unique_id("");
-	system(fmt("hostname > %s", tmpfile));
-	event add_hostname_reader(tmpfile);
-	}
\ No newline at end of file
+    {
+    Input::add_event([$source="hostname |",
+                      $name="SO-hostname",
+                      $reader=Input::READER_RAW,
+                      $want_record=F,
+                      $fields=HostnameCmdLine,
+                      $ev=SecurityOnion::hostname_line]);
+    }   
\ No newline at end of file
