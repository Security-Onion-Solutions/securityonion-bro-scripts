
event bro_init()
	{
	if ( ! reading_live_traffic() )
		return;

	Log::remove_default_filter(HTTP::LOG);
	Log::add_filter(HTTP::LOG, [$name = "http-interfaces",
	                            $path_func(id: Log::ID, path: string, rec: HTTP::Info) = 
	                            	{ 
					if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::WORKER )
					{
						local node = Cluster::node;
						if ( node in Cluster::nodes && Cluster::nodes[node]?$interface )
						{
							# If af_packet plugin is enabled, we need to strip "af_packet::" off the interface name
							local interfacename = Cluster::nodes[node]$interface;
							interfacename = subst_string(interfacename, "af_packet::", "");
							return cat("http_", interfacename);
						}
					}
	                            	else
	                            		return "http";
	                            	}
	                            ]);
	}
