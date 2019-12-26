@load ./sensortab

redef record Conn::Info += {
	sensorname: string &log &optional;
};

event connection_state_remove(c: connection)
	{
	c$conn$sensorname = SecurityOnion::sensorname;
	}

