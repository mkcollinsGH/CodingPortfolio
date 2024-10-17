/*
 * Author: marcus collins
 *
 * Version: 0.1.0
 *
 * Brief:
 * Demonstration code to perform the deciphering/decoding of a [circular] shift cipher.
 * The input is expected to be UTF-8 enciphered text, but strictly in the English/ASCII
 * code space (alphabet, punctuation, digits in the lower 256 codes). 
 */

/*
//----------//
// INCLUDES //
//----------//
*/ 

#include <ios>             // contains iostream formatting flags
#include <iostream>
#include <fstream>
#include <format>          // formatted strings with variables and specifiers, requires C++20
#include <filesystem>      // file checking, etc. requires C++17 at mininum
#include <stdexcept>       // standard exception std::invalid_argument
#include <string>
#include <string_view>     // read-only reference to std::string value
#include <valarray>        // for circular-shift functionality
#include <vector>
#include <map>             // act as a dictionary
#include <deque>           // double-ended queue (popping front and back)
#include <bitset>          // efficient storage of true/false values


/*
//---------//
// ALIASES //
//---------//
*/

// Convenience alias for the filesystem access functions and objects
namespace fsys = std::filesystem;

// Convenience namespace for ""s string literals and time shorthand notations
using namespace std::literals;

// Standard input (keyboard), output (terminal), error (terminal)
using std::cout;
using std::cin;
using std::cerr;
using std::endl;

// Standard file stream types (input & output respectively)
using std::ifstream;
using std::ofstream;

 // C++ style string objects and read-only reference
using std::string;
using std::string_view;


/*
//----------//
// TYPEDEFS //
//----------// 
*/

// Containers for strings, characters 
typedef std::vector<std::string> StrVec;
typedef std::deque<std::string> StrDeq;

typedef std::valarray<char> ChrVarr;

typedef std::map<char,char> ChrDict;


/*
//-----------------//
// CLASSES/OBJECTS //
//-----------------//
*/

// Enumerated object to hold program codes (mainly for command-line parsing errors)
//
enum DECIPHER_PROG_CODES : short int {
	CMDLN_USER_ERROR = -1,
	CMDLN_OK = 0,
	CMDLN_HELP_REQ = 1,
	CMDLN_USAGE_REQ = 2
};

// Dictionary "mapping" program codes to message strings
//
std::map<DECIPHER_PROG_CODES, std::string> DECIPHER_PROG_MSG = {
	{CMDLN_USER_ERROR, "Command-line enterd by user had errors."s},
	{CMDLN_OK, "Command-line entered parsed without errors."s},
	{CMDLN_HELP_REQ, "HELP message required or requested by user."s},
	{CMDLN_USAGE_REQ, "USAGE message required by user."s}
};

// Object to store user command-line entries and determine overall program
//   functionality
struct DecipherCtrlOpts 
{ 
	// Name of this compiled program as entered on the command-line
	//   and stripped of pathnames preceeding it
	string program_name;
	string prog_name_stripped;

	// Input & output filenames
	string infilename;
	string outfilename;
	
	// Shift amount entered by user on command-line.
	//   Default cipher shift amount is 5 characters.
	int orig_shift_len = 5;  

	// Calculated after user enters either negative or postive shift_amount
	//   to be strictly positive for modulo arithmetic
	//   Note: modulo arithmetic is used to eliminate unnecessary circular 
	//         shifts of the character maps
	int reduced_shift_len = 5;
	int digits_shift_len  = 0;
	int puncts_shift_len  = 0;

	// Dictionary (C++ map) to decipher alphabet, numbers and punctuation	
	ChrDict cipher_dict;

	// Number of characters read from the input file (and written to
	//   the output file)
	size_t nbytes_file = 0;


	// Flag storage as efficient as possible
	std::bitset<8> decipher_flags = 0b01000000;

	//decipher_flags[0] = false; // HELP or USAGE was needed or requested
	//decipher_flags[1] = true;  // default output name to be used (.dec extension appended by default)
	//decipher_flags[2] = false; // digits to be deciphered in input file
	//decipher_flags[3] = false; // punctuation symbols to be deciphered in input file 
	//decipher_flags[4] = false; // UNUSED FLAG
	//decipher_flags[5] = false; // UNUSED FLAG
	//decipher_flags[6] = false; // UNUSED FLAG
	//decipher_flags[7] = false; // display logging info for testing purposes
};


/*
//-----------//
// CONSTANTS //
//-----------//
*/

// Note: ChrVarr is used for these to enable the circular shift required during
//       dictionary creation

// uppercase [English] alphabet 
const ChrVarr ORIG_UPPERCASE = {
	'A','B','C','D','E','F','G','H','I','J',
	'K','L','M','N','O','P','Q','R','S','T',
	'U','V','W','X','Y','Z'
};

// lowercase [English] alphabet 
const ChrVarr ORIG_LOWERCASE = {
	'a','b','c','d','e','f','g','h','i','j',
	'k','l','m','n','o','p','q','r','s','t',
	'u','v','w','x','y','z'
};

// numberical digits as characters 
const ChrVarr ORIG_DIGITS = {
	'0','1','2','3','4','5','6','7','8','9'
};

// most punctuation symbols as individual characters 
//   placed in ASCII/UTF-8 order
const ChrVarr ORIG_PUNCTUATION_SYMBOLS = {
	'!', '"', '#', '$', '%', '&',
	'\'', '(', ')', '*', '+', ',', 
	'-', '.', '/', ':', ';', '<', 
	'=', '>', '?', '@', '[', '\\',
	']', '^', '_', '`', '{', '|', 
	'}', '~'
}; 


/*
//-----------------------//
// FUNCTION DECLARATIONS //
//-----------------------//
*/

// Function to calculate a reduced shift amount
int calcReducedShift(const int& original_shift, const int& mod_size = 26);

// Functions to print USAGE or HELP message to the user interface (terminal-based only)
void printUsage(string_view progname) noexcept;
void printHelp(string_view progname) noexcept;

// Functions to parse command-line or user-interface arguments/options
DECIPHER_PROG_CODES parseSingleCharOptions(string_view cmdlnSingles, DecipherCtrlOpts* ciphopts) noexcept;
DECIPHER_PROG_CODES parseCommandLine(const StrVec& usrCmdln, DecipherCtrlOpts* ciphopts);

// Create full deciphering dictionary (including alphabet, punctuation, digits
void generateCipherDict(DecipherCtrlOpts* ciphopts) noexcept;

// Read input file, decipher and write output file
void decipherFileText(DecipherCtrlOpts* ciphopts);

// Print log-like information to terminal screen
void printLogInfo(DecipherCtrlOpts* ciphopts) noexcept;


/*
//---------------//
// MAIN (DRIVER) //
//---------------//
*/
int main(int nargs, char* args[]) 
{
	// Program exit status (but prepend MY_ because EXIT_STATUS may exist already)
	int MY_EXIT_STATUS = 0;

	// Create storage for raw command-line and converted options/arguments
	StrVec raw_cmdln;
	DecipherCtrlOpts cmdopts;

	// Convert command-line entries to C++ strings and store in vector
	for(int n = 0; n < nargs; ++n) {
		raw_cmdln.emplace_back(args[n]);
	}

	// Start parsing the command-line and determine if deciphering text will proceed
	try
	{
		DECIPHER_PROG_CODES parse_res = parseCommandLine(raw_cmdln, &cmdopts);

		switch( parse_res ) {
			case CMDLN_HELP_REQ:
				printHelp(cmdopts.prog_name_stripped);
				MY_EXIT_STATUS = 0;
				break;
			case CMDLN_USAGE_REQ:
				printUsage(cmdopts.prog_name_stripped);
				MY_EXIT_STATUS = 0;
				break;
			case CMDLN_USER_ERROR:
				// This will not be reached because exception thrown by parseCommandLine()
				//   if this code occurs
				MY_EXIT_STATUS = 1;
				break;
			case CMDLN_OK:
				generateCipherDict(&cmdopts);

				decipherFileText(&cmdopts);

				if( cmdopts.decipher_flags[7] == true ) {
					printLogInfo(&cmdopts);
				}
				
				MY_EXIT_STATUS = 0;
				break;
		}// end switch()
	}
	catch( const std::invalid_argument& e) {
		cerr << e.what() << endl;
		MY_EXIT_STATUS = 1;
	}
	catch( const std::out_of_range& e ) {
		cerr << e.what() << endl;
		MY_EXIT_STATUS = 1;
	}
	catch( const fsys::filesystem_error& e ) {
		cerr << e.what() << endl;
		MY_EXIT_STATUS = 1;
	}
	catch( ... ) {
		// general catch-all error-handling
		cerr << "Unexpected error encountered. Program terminated." << endl;
		MY_EXIT_STATUS = 1;
	}

	// Exit program
	return(MY_EXIT_STATUS);
}


/*
//----------------------//
// FUNCTION DEFINITIONS //
//----------------------//
*/

/*
 * calcReducedShift
 *
 * Description: 
 *   Calculates a reduced shift amount based on whether
 *   the entered shift amount is negative or positive to protect against
 *   unnecessary shifting if the requested shift amount is greater than the
 *   size of the alphabet.
 *   Defaults to the size of the English alphabet (26).
 *
 *   Note:
 *    If this were not a privately-scoped function (meaning it is not defined or 
 *    declared in a header), then mod_size would need to be checked for 0
 *    or less than 0. 
 *    But, in this case, only access to the source code could be used to cause 
 *    undefined or error-causing behavior.
 *
 * Input:
 *  original_shift -> shift amount entered by user (remains unchanged by program)
 *  mod_size       -> size of the "alphabet" (to be used on different sized sets of characters)
 *
 * Output:
 *  Integer reduced modulo-N (mod_size)
 */
int calcReducedShift(const int& original_shift, const int& mod_size) 
{
	int reduced_shift = 0;
	if( original_shift < 0 ) {
		reduced_shift = original_shift;
		while( reduced_shift < 0 ) {
			reduced_shift += mod_size;
		}
	}
	else if( original_shift >= 0 ) {
		reduced_shift = original_shift % mod_size;
	}

	return(reduced_shift);
}


/*
 * printUsage
 *
 * Description:
 * Prints a simple usage without a full listing of options and their descriptions.
 *
 * Input:
 * progname -> name of the program (read-only)
 *
 * Output:
 * None (Disallowed)
 */
void printUsage(string_view progname) noexcept
{
	cout << endl;
	cout << "Usage:" << endl;
	cout << progname << " -i <IFILE>             to read IFILE input file and default output IFILE.ciph" << endl;
	cout << progname << " -i <IFILE> -o <OFILE>  to control name of output file" << endl;
	cout << endl;
	cout << progname << " -h" << endl;
	cout << progname << " --help";
	cout << "   for full HELP message" << endl;
	cout << endl;
	return;
}


/*
 * printHelp
 *
 * Description:
 * Prints the full HELP message with option descriptions, etc.
 *
 * Input:
 * progname -> name of the program (read-only)
 *
 * Output:
 * None (Disallowed)
 */
void printHelp(string_view progname) noexcept
{
	string help_spacer;
	help_spacer.assign(27, ' ');

	cout << endl;
	cout << "\e[1mUsage\e[0m:"s << endl;
	cout << progname << " [options] -i <IFILE> [-o <OFILE>]"s << endl;
	cout << endl;
	cout << "\e[1mRequired\e[0m:"s << endl;
	cout << "  -i <IFILE>,"s << endl;
    cout << "  --ifile <IFILE>   "s;
	cout << "Name of input file to read (must be UTF-8/ASCII text)"s << endl;
	cout << endl;
	cout << "\e[1mOptions\e[0m:"s << endl;
	cout << "  -o <OFILE>,"s << endl;
    cout << "  --ofile <OFILE>          "s;
	cout << "Name of output file to write (will be overwritten if exists)"s << endl;
	cout << help_spacer;
	cout << "Default filename created by appending \".dec\" to IFILE if option not used"s << endl;
	cout << endl;
	cout << "  -s <SHIFT>,"s << endl;
	cout << "  --shift-amount <SHIFT>   "s;
	cout << "Number of characters that each alphabet was shifted during enciphering (\e[1;3mDefault\e[0m: 5)"s << endl;
	cout << help_spacer;
	cout << "\e[1mNote\e[0m: Positive and Negative Integers are allowed."s << endl;
	cout << endl;
	cout << "  -n, --shift-numbers      "s;
	cout << "Include numberical digits in shifted/deciphered alphabet (\e[1;3mDefault\e[0m: FALSE)"s << endl;
	cout << "  -p, --shift-puncts       "s;
	cout << "Include punctuation symbols in shifted/deciphered alphabet (\e[1;3mDefault\e[0m: FALSE)"s << endl;
	cout << "  -a, --shift-all          "s;
	cout << "Include both numbers and punctuation symbols in shifted dictionary (\e[1;3mDefault\e[0m: FALSE)"s << endl;
	cout << endl;
	cout << "  -h, --help               "s;
	cout << "Print \e[1;4mHELP\e[0m message and stop without processing"s << endl;
	cout << endl;
	cout << "\e[1mExamples\e[0m:"s << endl;
	cout << "\t" << progname << " -a -i hello.txt"s << endl;
	cout << "\t" << progname << " -np -s 15 -i what.txt.enc -o this.dec"s << endl;
	cout << "\t" << progname << " --ofile temp.txt --ifile perm.enciph -pn -s -80"s << endl;
	cout << endl;
	return;
}


/*
 * parseSingleCharOptions
 *
 * Description:
 * Parses user-entered collected single-character argument/options/flags.
 *   This only applies to options/flags that do not have a follow-on value
 *   associated with the flag.
 *   Examples: 
 *     -xyz will be three different flags 'x', 'y' and 'z'.
 *     -f -g will be two different flags 'f', 'g' both parsed separtely.
 *     -n 44 will be invalidated by the calling parseCommandLine when '44' is read
 *           as a standalone option/flag/argument
 *
 * Input:
 * cmdlnSingles -> user-entered, single-character argument (read-only)
 * ciphopts     -> decipher program controller
 *
 * Output:
 * DECIPHER_PROG_CODES (enum) -> Way to indicate success, failure or help wanted/needed
 *
 * Exception(s):
 * None -> Disallowed
 */
DECIPHER_PROG_CODES parseSingleCharOptions(string_view cmdlnSingles, DecipherCtrlOpts* ciphopts) noexcept
{
	DECIPHER_PROG_CODES parse_results = CMDLN_OK;

	// If "--" is used or "-" is anywhere other than first position, 
	//   an invalid argument was entered
	if( cmdlnSingles.find_last_of('-') > 0 ) {
		parse_results = CMDLN_USER_ERROR;
	}

	// Begin checking each character in the combined singles argument string
	if( parse_results == CMDLN_OK ) {
		string_view::iterator arg_char_pos = cmdlnSingles.begin();
		std::advance(arg_char_pos, 1);

		while( arg_char_pos != cmdlnSingles.end() ) {
			switch( *arg_char_pos ) {
				case 'a':
					ciphopts->decipher_flags[2] = true;
					ciphopts->decipher_flags[3] = true;
					break;
				case 'n':
					ciphopts->decipher_flags[2] = true;
					break;
				case 'p':
					ciphopts->decipher_flags[3] = true;
					break;
				case 'l':
					ciphopts->decipher_flags[7] = true;
					break;
				case 'h':
					ciphopts->decipher_flags[0] = true;

					parse_results = CMDLN_HELP_REQ;
					break;
				default:
					ciphopts->decipher_flags[2] = false;
					ciphopts->decipher_flags[3] = false;
					ciphopts->decipher_flags[7] = false;
					ciphopts->decipher_flags[0] = false;
					
					parse_results = CMDLN_USER_ERROR;
					break;
			}

			std::advance(arg_char_pos, 1);
		}// end while(arg_char_pos)
	}

	return(parse_results);
}


/*
 * parseCommandLine
 *
 * Description:
 * Parses user-entered command-line for proper options or HELP. 
 *  Handles stripping of program name to name-only instead of full path.
 *
 * Input:
 * usr_cmdln -> user-entered command-line as C++ style strings
 * ciphopts  -> pointer to object to hold results of parsed/evaluated options
 *
 * Output:
 * DECIPHER_PROG_CODES (enum) -> Program codes to indicate command-line parsing successful or failed
 *
 * Exception:
 * std::invalid_argument -> conversion of intergers incorrect (bad input like 'A')
 *                       -> bad single-character option entered
 *
 * std::out_of_range -> conversion of intergers incorrect (too large for signed integer)
 */
DECIPHER_PROG_CODES parseCommandLine(const StrVec& usr_cmdln, DecipherCtrlOpts* ciphopts)
{
	DECIPHER_PROG_CODES parse_results = CMDLN_OK;

	// Start at beginning of command-line, grab program name and go from there
	StrDeq cmdln_deq;

	cmdln_deq.assign(usr_cmdln.begin(), usr_cmdln.end());

	string_view curr_arg = cmdln_deq.front();

	ciphopts->program_name.assign(curr_arg.begin(), curr_arg.end());
	ciphopts->prog_name_stripped.assign(fsys::path(curr_arg).filename().string());

	cmdln_deq.pop_front();

	// Check for program name only and print usage if so
	if( cmdln_deq.empty() ) {
		parse_results = CMDLN_USAGE_REQ;

		return(parse_results);
	}

	// Evaluate each option and convert if necessary
	while( not cmdln_deq.empty() ) {
		curr_arg = cmdln_deq.front();

		if( (curr_arg.compare("-i"sv) == 0) or
		    (curr_arg.compare("--ifile"sv) == 0) ) 
		{
			cmdln_deq.pop_front();
			ciphopts->infilename = cmdln_deq.front();
			cmdln_deq.pop_front();
		}
		else if( (curr_arg.compare("-o"sv) == 0) or
		         (curr_arg.compare("--ofile"sv) == 0) ) 
		{
			cmdln_deq.pop_front();
			ciphopts->outfilename = cmdln_deq.front();
			ciphopts->decipher_flags[1] = false;
			cmdln_deq.pop_front();
		}
		else if( (curr_arg.compare("-s"sv) == 0) or
		         (curr_arg.compare("--shift-amount"sv) == 0) ) 
		{
			cmdln_deq.pop_front();
			string tmp_int_str = cmdln_deq.front();

			try {
				ciphopts->orig_shift_len = std::stoi(tmp_int_str, nullptr, 10);
				cmdln_deq.pop_front();
			}
			catch(const std::invalid_argument& e) {
				throw e;
			}
			catch(const std::out_of_range& e) {
				throw e;
			}
		}
		else if( (curr_arg.compare("--shift-numbers"sv) == 0) ) 
		{
			ciphopts->decipher_flags[2] = true;
			cmdln_deq.pop_front();
		}
		else if( (curr_arg.compare("--shift-puncts"sv) == 0) ) 
		{
			ciphopts->decipher_flags[3] = true;
			cmdln_deq.pop_front();
		}
		else if( (curr_arg.compare("--shift-all"sv) == 0) ) 
		{
			ciphopts->decipher_flags[2] = true;
			ciphopts->decipher_flags[3] = true;
			cmdln_deq.pop_front();
		}
		else if( (curr_arg.compare("--help"sv) == 0) ) 
		{
			ciphopts->decipher_flags[0] = true;
			parse_results = CMDLN_HELP_REQ;
			cmdln_deq.clear();
		}
		else if( (curr_arg.compare("--show-log"sv) == 0) ) 
		{
			ciphopts->decipher_flags[7] = true;
			cmdln_deq.pop_front();
		}
		else
		{
			// Parse the single character options
			parse_results = parseSingleCharOptions(curr_arg, ciphopts);

			// If the overall argument is not valid, use this error message
			string ia_errmsg = std::format(
				"\nInvalid argument ({}) used. Please see HELP with -h or --help option.\n", 
				curr_arg);

			switch( parse_results ) {
				case CMDLN_USER_ERROR:
					cmdln_deq.clear();
					throw std::invalid_argument(ia_errmsg);
					break;
				case CMDLN_HELP_REQ:
				case CMDLN_USAGE_REQ:
					cmdln_deq.clear();
					break;
				default:
					cmdln_deq.pop_front();
					break;
			}
		}// end if-elseif-else
		
	}// end while()

	return(parse_results);
}


/*
 * generateCipherDict
 *
 * Description:
 * Generate the necessary alphabet, punctuation and number mappings to put
 *  into a single map/dictionary for deciphering text.
 *
 * Input:
 * ciphopts -> object containing cipher options/controls [pointer]
 *
 * Output:
 * None (Disallowed)
 */
void generateCipherDict(DecipherCtrlOpts* ciphopts) noexcept
{
	// Shift amount for regular uppercase & lowercase alphabet
	ciphopts->reduced_shift_len = calcReducedShift(ciphopts->orig_shift_len);

	// Shift amounts for numberical digits, punctuation symbols, both or neither.
	if( ciphopts->decipher_flags[2] == true ) {
		ciphopts->digits_shift_len = calcReducedShift(
			ciphopts->orig_shift_len, static_cast<int>(ORIG_DIGITS.size()));
	}

	if( ciphopts->decipher_flags[3] == true ) {
		ciphopts->puncts_shift_len = calcReducedShift(
			ciphopts->orig_shift_len, static_cast<int>(ORIG_PUNCTUATION_SYMBOLS.size()));
	}

	// Copies of the character arrays to be circularly shifted.
	//   Shift arrays as needed and create the final dictionary.
	ChrVarr shifted_uppercase = ORIG_UPPERCASE.cshift(ciphopts->reduced_shift_len);
	ChrVarr shifted_lowercase = ORIG_LOWERCASE.cshift(ciphopts->reduced_shift_len);
	ChrVarr shifted_digits    = ORIG_DIGITS.cshift(ciphopts->digits_shift_len);
	ChrVarr shifted_puncts    = ORIG_PUNCTUATION_SYMBOLS.cshift(ciphopts->puncts_shift_len);
	
	for(size_t n = 0; n < shifted_uppercase.size(); ++n) {
		ciphopts->cipher_dict[shifted_uppercase[n]] = ORIG_UPPERCASE[n];
	}

	for(size_t n = 0; n < shifted_lowercase.size(); ++n) {
		ciphopts->cipher_dict[shifted_lowercase[n]] = ORIG_LOWERCASE[n];
	}

	for(size_t n = 0; n < shifted_digits.size(); ++n) {
		ciphopts->cipher_dict[shifted_digits[n]] = ORIG_DIGITS[n];
	}

	for(size_t n = 0; n < shifted_puncts.size(); ++n) {
		ciphopts->cipher_dict[shifted_puncts[n]] = ORIG_PUNCTUATION_SYMBOLS[n];
	}

	return;
}


/*
 * decipherFileText
 *
 * Description:
 * Checks for the existence of the input filename, throws exception if it does not 
 *   exist. If it does exist, reads text (line-by-line) and deciphers the text.
 *   If the output file exists, it is overwritten without asking.
 *
 * Input:
 * ciphopts -> object storing program controls/options [pointer]
 *
 * Output:
 * None (throws exception for FILE NOT FOUND)
 */
void decipherFileText(DecipherCtrlOpts* ciphopts)
{
	// Error message just in case there are filestream problems
	string errmsg{"Deciphering text file problem."};
	std::error_code ec;
	
	// Form the file pathnames and check for existence
	// Input text file
	fsys::path ifilepath( ciphopts->infilename );
	std::ifstream ifile;

	if( not fsys::exists(ifilepath) ) {
		ec = std::make_error_code(std::errc::no_such_file_or_directory);
		throw fsys::filesystem_error(errmsg, ifilepath, ec);
		return;
	}
	else {
		ifile.open(ifilepath);
	}

	// Output text file
	if( ciphopts->decipher_flags[1] == true ) {
		string oname_full(ciphopts->infilename);
		oname_full = oname_full.append(".dec");
		ciphopts->outfilename = oname_full;
	}

	fsys::path ofilepath( ciphopts->outfilename );

	std::ofstream ofile(ofilepath);

	if( not ofile.is_open() ) {
		if( ifile.is_open() ) { ifile.close(); }

		ec = std::make_error_code(std::errc::no_message);
		throw fsys::filesystem_error(errmsg, ofilepath, ec);
		return;
	}

	// Read input stream and write deciphered output stream
	
	size_t num_chrs_read{0};

	string origstr, outstr;
	while( std::getline(ifile, origstr) ) {
		for(size_t n = 0; n < origstr.size(); ++n, ++num_chrs_read, ciphopts->nbytes_file++) {
			if(ciphopts->cipher_dict.contains(origstr[n])) {
				outstr.push_back(ciphopts->cipher_dict[origstr[n]]);
			}
			else {
				outstr.push_back(origstr[n]);
			}
		}

		ofile << outstr << endl;

		origstr.clear();
		outstr.clear();
	}// end while()

	// Close file (clean-up)
	if( ifile.is_open() ) { ifile.close(); }
	if( ofile.is_open() ) { ofile.close(); }

	// Print to screen the number of characters read
	if( not ciphopts->decipher_flags[7] ) {
		cout << endl;
		cout << std::format("Read {:d} characters from the input file.", num_chrs_read) << endl;
		cout << endl;
	}
	
	return;
}


/*
 * printLogInfo
 *
 * Description:
 * Prints log-like information to terminal screen.
 *   Information such as name of program, input/output filenames, control 
 *   options, etc.
 *
 * Input:
 * ciphopts -> object containing program control options/values [pointer]
 *
 * Output:
 * None
 */
void printLogInfo(DecipherCtrlOpts* ciphopts) noexcept 
{
	// Create a text-border for printing to terminal
	string border;
	border.assign(45, '=');

	// Info to print to terminal about program controls
	cerr << endl;
	cerr << border << endl;
	cerr << "Decipher program options/control" << endl;
	cerr << border << endl;
	cerr << "[Raw] Program name:  " << ciphopts->program_name << endl;
	cerr << "[Stripped] Name:     " << ciphopts->prog_name_stripped << endl;
	cerr << "IFILE:               " << ciphopts->infilename << endl;
	cerr << "OFILE:               " << ciphopts->outfilename << endl;
	cerr << "Default output name: " << std::boolalpha << ciphopts->decipher_flags[1] << endl;
	cerr << "Shift amount:        " << ciphopts->orig_shift_len << endl;
	cerr << "[Reduced] Shift:     " << ciphopts->reduced_shift_len << endl;
	cerr << "Shift numbers:       " << std::boolalpha << ciphopts->decipher_flags[2] << endl;
	cerr << "Number shift amount: " << ciphopts->digits_shift_len << endl;
	cerr << "Shift punctuation:   " << std::boolalpha << ciphopts->decipher_flags[3] << endl;
	cerr << "Punct. shift amount: " << ciphopts->puncts_shift_len << endl;

	cerr << "Decipher dictionary: {";
	ChrDict::iterator dIter = ciphopts->cipher_dict.find('A');

	for(size_t n = 0; n < 10; ++n, std::advance(dIter,1)) 
	{
		cerr << "(" << std::get<0>(*dIter) << "," << std::get<1>(*dIter) << "), ";
	}
	cerr << "...}" << endl;

	cerr << "Number chars read:   " << ciphopts->nbytes_file << endl;
	cerr << border << endl;
	cerr << endl;
	
	return;
}
