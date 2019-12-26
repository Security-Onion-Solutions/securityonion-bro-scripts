module SecurityOnion;

export {
	## Read a file.  This function *must* be called from within 
	## a "when" statement since it's an asynchronous function.
	##
	## filename: The full path and filename to read off disk.
	##
	## Returns: The contents of the file as a string.
	global readfile: function(filename: string): string;
}

global outstanding_reads: table[string] of string = table();
global complete_reads: set[string] = set();

type Line: record {
	l: string;
};

event read_entry(desc: Input::EventDescription, tpe: Input::Event, line: string)
	{
	if ( desc$name in outstanding_reads ) 
		{
		outstanding_reads[desc$name] += line + "\n";
		}
	}

event Input::end_of_data(name: string, source:string)
	{
	if ( name in complete_reads )
		delete complete_reads[name];
	}

function readfile(filename: string): string
	{
	local id = unique_id("SOrfile");
	outstanding_reads[id] = "";
	add complete_reads[id];
	
	Input::add_event([$source=filename,
	                  $reader=Input::READER_RAW,
	                  $mode=Input::MANUAL,
	                  $name=id,
	                  $fields=Line,
	                  $want_record=F,
	                  $ev=read_entry]);

	return when ( id !in complete_reads )
		{
		local output = outstanding_reads[id];
		delete outstanding_reads[id];
		Input::remove(id);
		return output;
		}
	}
