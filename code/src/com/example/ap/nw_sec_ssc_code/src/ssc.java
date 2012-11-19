class ssc
{
	/* Implementation of a short-string comparison that outputs 3- to 8-character long strings for the user to compare.
	 * The current implementation is to take however many hex digits a hash function outputs (such as 40 for SHA-1, 64
	 * or 128 for non-truncated versions of SHA-2 and SHA-3), chop it up into 16-hex digit substrings, add up the 
	 * decimal value of each substring, and take the (result % 93)+33 to produce a character. Doing so allows each
	 * value to be mapped directly to a printable ASCII character for the user to see.
	 * 
	 * Modulus is used because it was the simplest of the two methods that were considered. The other is:
	 * 
	 *		if sum(each 16 hex digits) > 90, split the string in two and perform the same test until it is <= 90.
	 *  	When this is true, save off the value and turn it into an ASCII character as above. Then take up to only the 
	 *		first 8 characters for the user string.
	 *	
	 *	Performed this way because for how we're using it, SSC's purpose isn't security, but rather to make it easy for
	 *	a user to visually compare values and determine if they are the same. The SSC value is derived from or acquired 
	 *	from places	that are secured, such as the AP (where the user generates the SSC based on the airport's public key
	 *	(which can be validated by checking if the CA's signature is correct) or the NFC tag (where the SSC is actually
	 *	stored and signed by the airport's private key.
	 */
	
	/*How many hex chars of the hash to grab for each operation. 
	 * Length of SSC will be size (in bits) of hash / CHUNK_SIZE. */
	private static final int CHUNK_SIZE = 16; 
	private static final int ASCII_MIN = 33; //smallest value of printable ASCII character
	private static final int ASCII_MAX = 126; //largest value of printable ASCII character
	
	/* 93 printable chars in ASCII table. Use one of them for each char displayed to user. */
	private static final int PRINTABLE_CHARS = ASCII_MAX - ASCII_MIN; 
		
	public static void main(String [] args)
	{
		String hash_val = "d135bb84d0439dbaca32247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"; //SHA-3 hash
		//String hash_val = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"; //SHA-1 hash
		//String hash_val = args[0]; //if we're getting the hash value from another source, as I'd imagine we ultimately will be.
	
		/* Setup local variables */
		char ret_val;
		StringBuffer short_str = new StringBuffer(); //what is displayed to user
		int max_len = hash_val.length();
		int i, chunk_sum = 0;
		
		//System.out.print("Original hash val: "+hash_val+"\n");
		for(i=0; i<max_len; i+=CHUNK_SIZE)
		{
			ret_val = create_char(hash_val, i, chunk_sum);
			if(ret_val == 0) //failed to create a valid char
				return;
			
			short_str.append(ret_val); 
			chunk_sum = (int)ret_val; //get its newest value
			
			if((i+CHUNK_SIZE)!=max_len && (max_len-(i+CHUNK_SIZE)) < CHUNK_SIZE) //we have a short last chunk
			{
				ret_val = create_char(hash_val, i, chunk_sum);
				if(ret_val == 0) //failed to create a valid char
					return;
				short_str.append(ret_val);
				chunk_sum = (int)ret_val; //get its newest value
				break; //last chunk, so we're done
			}
		}
		System.out.print("User display string is "+short_str.toString()); //display SSC on screen
	}
	
	public static char create_char(String hash_val, int i, int chunk_sum)
	{
		/* Create each character of the short string. Prints error message if the
		 * string could not be created for any reason.
		 */
		
		String hash_chunk;
		char[] chunk_array;
		int j;
		
		hash_chunk = hash_val.substring(i, i+CHUNK_SIZE);
		//System.out.print(hash_chunk+"\n");
		chunk_array = hash_chunk.toCharArray();
		
		for(j=0; j<hash_chunk.length(); j++)
		{
			chunk_sum += Integer.parseInt(chunk_array[j]+"", 16); //increment by decimal value of hex char
			//System.out.print("Value is "+chunk_array[j]+"\n"); 
		}
		chunk_sum %= PRINTABLE_CHARS;
		//System.out.print("Sum is "+chunk_sum+"\n");
		chunk_sum += ASCII_MIN; //make sure it's a printable character
		
		if(chunk_sum < ASCII_MIN || chunk_sum > ASCII_MAX) //verify for sure
		{
			System.out.print("Failed to create string.\n");
			return 0; //we failed
		}
		return (char)chunk_sum;
	}
}