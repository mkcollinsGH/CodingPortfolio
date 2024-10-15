/*
 * Author: marcus collins
 *
 * Version: 0.1.0
 *
 * Brief:
 * Demonstration code to perform the deciphering/decoding of a [circular] shift cipher.
 * The input is expected to be UUTF-8 enciphered text, but strictly in the English/ASCII
 * code space (alphabet, punctuation, digits in the lower 256 codes). 
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
#include <set>
#include <bitset>          // efficient storage of true/false values
//#include <unordered_map>
//#include <print>           // formatted file-stream or character-stream printing, requires C++23 

/*
//---------//
// ALIASES //
//---------//
*/

// Convenience alias for the filesystem access functions and objects
namespace fsys = std::filesystem;

// Convenience namespace for ""s string literals and time shorthand notations
using namespace std::literals;

// standard input (keyboard), output (terminal), error (terminal)
using std::cout;
using std::cin;
using std::cerr;
using std::endl;

// standard file stream types (input & output respectively)
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
typedef std::valarray<char> ChrVarr;

typedef std::map<char,char> ChrDict;
typedef std::set<char> ChrSet;


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
	bool use_default_oname = true;  // an extension (.dec) will be appended to infilename
	
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

	bool dec_numbers = false;  // decipher numbers from input file
	bool dec_puncts  = false;  // decipher punctation from input file

	// Dictionary (C++ map) to decipher alphabet, numbers and punctuation	
	ChrDict cipher_dict;

	// Number of characters read from the input file (and written to
	//   the output file)
	size_t nbytes_file = 0;

	// Flag to show information as the program is running for testing purposes
	bool display_log_info = false;

	// Flag storage as efficient as possible
	std::bitset<8> decipher_flags = 0b01000000;

	//decipher_flags[1] = true;  // default output name to be used
	//decipher_flags[2] = false; // digits to be deciphered in input file
	//decipher_flags[3] = false; // punctuation symbols to be deciphered in input file 
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

// numbers as characters 
const ChrVarr ORIG_DIGITS = {
	'0','1','2','3','4','5','6','7','8','9'
};

// most punctuation as individual characters 
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
int parseCommandLine(const StrVec& usrCmdln, DecipherCtrlOpts* ciphopts);
//DECIPHER_PROG_CODES parseCommandLine(const StrVec& usrCmdln, DecipherCtrlOpts* ciphopts);

// create full deciphering dictionary (including alphabet, punctuation, numbers
void generateCipherDict(DecipherCtrlOpts* ciphopts) noexcept;

// read input file, decipher and write output file
void decipherFileText(DecipherCtrlOpts* ciphopts);

// Print log-like information to terminal screen
void printLogInfo(DecipherCtrlOpts* ciphopts) noexcept;


/*
//---------------//
// MAIN (DRIVER) //
//---------------//
*/
int main(int nargs, char* args[]) {
	// create storage for raw command-line and converted options/arguments
	StrVec raw_cmdln;
	DecipherCtrlOpts cmdopts;

	// convert command-line entries to C++ strings and store in vector
	for(int n = 0; n < nargs; ++n) {
		raw_cmdln.push_back(string(args[n]));
	}

	try
	{
		// can throw an std::invalid_argument exception
		int parse_res = parseCommandLine(raw_cmdln, &cmdopts);
		//DECIPHER_PROG_CODES parse_res = parseCommandLine(raw_cmdln, &cmdopts);

		if( parse_res == 1 ) {
			// user either needed USAGE or HELP printed
			/*if( cmdopts.decipher_flags[7] == true ) {
			 * cerr << endl << DECIPHER_PROG_MSG[parse_res] << endl;
			  }
			 */
			return(0);
		}
		else if( parse_res == 0 ) {
			generateCipherDict(&cmdopts);

			// can throw a filesystem_error exception
			decipherFileText(&cmdopts);

			// print log-like info
			if( cmdopts.display_log_info ) {
				printLogInfo(&cmdopts);
			}
		}// end if-elseif(parse_res)
	}
	catch( const std::invalid_argument& e) {
		cerr << e.what() << endl;
		return(1);
	}
	catch( const std::out_of_range& e ) {
		cerr << e.what() << endl;
		return(1);
	}
	catch( const fsys::filesystem_error& e ) {
		cerr << e.what() << endl;
		return(1);
	}
	catch( ... ) {
		// general catch-all error-handling
		cerr << "Unexpected error encountered. Program terminated." << endl;
		return(1);
	}

	// exit successfully
	return(0);
}

/*
//----------------------//
// FUNCTION DEFINITIONS //
//----------------------//
*/

/* 
 *   Description: 
 *   Calculates a reduced shift amount based on whether
 *   the entered shift amount is negative or positive to protect against
 *   unnecessary shifting if the requested shift amount is greater than the
 *   size of the alphabet.
 *   Defaults to the size of the English alphabet (26).
 *
 *   Note:
 *   If this were not a privately-scoped function (meaning it is not defined or 
 *   declared in a header), then mod_size would need to be checked for 0
 *   or less than 0. 
 *   But, in this case, only access to the source code could be used to cause 
 *   undefined or error-causing behavior.
 *
 *   Input:
 *   original_shift -> shift amount entered by user (remains unchanged by program)
 *   mod_size       -> size of the "alphabet" (to be used on different sized sets of characters)
 *
 *   Output:
 *   Integer reduced modulo-N (mod_size)
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
 * Description:
 * Prints a simple usage without a full listing of options and their descriptions.
 *
 * Input:
 * progname -> name of the program
 *
 * Output:
 * None (prints to terminal screen --> std::cout)
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
 * Description:
 * Prints the full HELP message with option descriptions, etc.
 *
 * Input:
 * progname -> name of the program
 *
 * Output:
 * None (prints to terminal screen --> std::cout)
 */
void printHelp(string_view progname) noexcept
{
	cout << endl;
	cout << "Usage:" << endl;
	cout << progname << " [options]";
	cout << " -i <IFILE> [-o <OFILE>]" << endl;
	cout << endl;
	cout << "Required:" << endl;
	cout << "  -i, --ifile <IFILE>   ";
	cout << " \tName of input file to read (must be UTF-8/ASCII text)" << endl;
	cout << endl;
	cout << "Options:" << endl;
	cout << "  -o, --ofile <OFILE>   ";
	cout << " \tName of output file to write (will be overwritten if exists)" << endl;
	cout << "                        ";
	cout << " \tDefault filename created by appending \".dec\" to IFILE if option not used" << endl;
	cout << endl;
	cout << "  -s <SHIFT>," << endl;
	cout << "  --shift-amount <SHIFT>";
	cout << " \tNumber of characters alphabet was shifted during enciphering (default: 5)" << endl;
	cout << endl;
	cout << "  -n, --shift-nums      ";
	cout << " \tInclude numbers in shifted/deciphered alphabet (default: false)" << endl;
	cout << "  -p, --shift-puncts    ";
	cout << " \tInclude punctuation in shifted/deciphered alphabet (default: false)" << endl;
	cout << "  -a, --shift-all       ";
	cout << " \tInclude both numbers and punctuation in shifted dictionary (default: false)" << endl;
	cout << endl;
	cout << "  -h, --help            ";
	cout << " \tPrint HELP message and stop without processing" << endl;
	cout << endl;
	cout << "Example uses:" << endl;
	cout << "\t" << progname << " -a -i hello.txt" << endl;
	cout << "\t" << progname << " -np -s 15 -i what.txt.enc -o this.dec" << endl;
	cout << "\t" << progname << " --ofile temp.txt --ifile perm.enciph -pn -s -80" << endl;
	cout << endl;
	return;
}


/*
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
 * cmdlnSingles -> user-entered, single-character argument
 * ciphopts     -> decipher program controller
 *
 * Output:
 * DECIPHER_PROG_CODES (enum) -> Way to indicate success, failure or help wanted/needed
 *
 * Exception(s):
 * none -> Disallowed
 */
DECIPHER_PROG_CODES parseSingleCharOptions(string_view cmdlnSingles, DecipherCtrlOpts* ciphopts) noexcept
{
	DECIPHER_PROG_CODES parse_results = CMDLN_OK;

	if( cmdlnSingles.find_last_of("-"s) > 0 ) {
		parse_results = CMDLN_USER_ERROR;
	}

	if( parse_results == CMDLN_OK ) {
		string_view::const_iterator arg_char_pos = cmdlnSingles.begin();
		std::advance(arg_char_pos, 1);
	}

	return(parse_results);
}


/*
 * Description:
 * Parses user-entered command-line for proper options or HELP. 
 *  Handles stripping of program name to name-only instead of full path.
 *
 * Input:
 * usr_cmdln -> user-entered command-line as C++ style strings
 * ciphopts  -> pointer to object to hold results of parsed/evaluated options
 *
 * Output:
 * parse_results -> Integer to indicate successful parsing/evaluation or HELP message requested
 *
 * Exception:
 * std::invalid_argument -> conversion of intergers incorrect (bad input like 'A')
 *                       -> bad single-character option entered
 *
 * std::out_of_range -> conversion of intergers incorrect (too large for signed integer)
 */
int parseCommandLine(const StrVec& usr_cmdln, DecipherCtrlOpts* ciphopts)
{
	// 0: command-line parsed successfully, continue program as intended
	// 1: help printed to screen, stop program without failure status/code
	int parse_results = 0;

	// Start at beginning of command-line, grab program name and go from there
	size_t opt_number = 0;
	string curropt;

	ciphopts->program_name.append(usr_cmdln.at(opt_number));
	ciphopts->prog_name_stripped.append(fsys::path(usr_cmdln.at(opt_number)).filename().string());

	++opt_number;

	// check for program name only and print usage if so
	if( usr_cmdln.size() == 1 ) {
		parse_results = 1;

		printUsage(ciphopts->prog_name_stripped);

		return(parse_results);
	}

	// evaluate each option and convert if necessary
	while( opt_number < usr_cmdln.size() ) {
		curropt = usr_cmdln.at(opt_number);

		if( (curropt.compare("-i") == 0) or
		    (curropt.compare("--ifile") == 0) ) 
		{
			ciphopts->infilename = usr_cmdln.at(opt_number + 1);
			opt_number += 2;
		}
		else if( (curropt.compare("-o") == 0) or
		         (curropt.compare("--ofile") == 0) ) 
		{
			ciphopts->outfilename = usr_cmdln.at(opt_number + 1);
			ciphopts->use_default_oname = false;
			opt_number += 2;
		}
		else if( (curropt.compare("-s") == 0) or
		         (curropt.compare("--shift-amount") == 0) ) 
		{
			string currarg = usr_cmdln.at(opt_number + 1);

			try {
				ciphopts->orig_shift_len = std::stoi(currarg, nullptr, 10);
				opt_number += 2;
			}
			catch(const std::invalid_argument& e) {
				throw e;
			}
			catch(const std::out_of_range& e) {
				throw e;
			}
		}
		else if( (curropt.compare("--shift-nums") == 0) ) 
		{
			ciphopts->dec_numbers = true;
			opt_number += 1;
		}
		else if( (curropt.compare("--shift-puncts") == 0) ) 
		{
			ciphopts->dec_puncts = true;
			opt_number += 1;
		}
		else if( (curropt.compare("--shift-all") == 0) ) 
		{
			ciphopts->dec_numbers = true;
			ciphopts->dec_puncts  = true;
			opt_number += 1;
		}
		else if( (curropt.compare("--help") == 0) ) 
		{
			parse_results = 1;
			printHelp(ciphopts->prog_name_stripped);
			opt_number = usr_cmdln.size();
		}
		else if( (curropt.compare("--show-log") == 0) ) 
		{
			ciphopts->display_log_info = true;
			opt_number += 1;
		}
		else
		{
			// check for collection of single-value options combined into
			//   a string or individually
			bool valid_sco_used = false;

			//string curropt = usr_cmdln.at(opt_number);
			std::set<char> valid_singlechr_opts = {'a', 'l', 'n', 'p', 'h'};

			// if the overall argument is not valid, use this error message
			string ia_errmsg = std::format(
				"\nInvalid argument ({}) used. Please see HELP with -h or --help option.\n", 
				curropt);

			if( curropt.find_last_of('-') > 0 ) {
				throw std::invalid_argument(ia_errmsg);
			}

			valid_sco_used = true;
			for(size_t n = 1; n < curropt.size(); ++n) {
				if(valid_singlechr_opts.contains(curropt[n])) {
					switch(curropt[n]) 
					{
						case 'a':
							ciphopts->dec_numbers = true;
							ciphopts->dec_puncts  = true;
							break;
						case 'n':
							ciphopts->dec_numbers = true;
							break;
						case 'p':
							ciphopts->dec_puncts = true;
							break;
						case 'l':
							ciphopts->display_log_info = true;
							break;
						case 'h':
							printHelp(ciphopts->prog_name_stripped);
							parse_results = 1;
							opt_number = usr_cmdln.size();
							break;
					}// end switch()
				}
				else {
					valid_sco_used = false;
					ciphopts->display_log_info = false;
					ciphopts->dec_numbers = false;
					ciphopts->dec_puncts = false;

					ciphopts->decipher_flags[7] = false;
					ciphopts->decipher_flags[2] = false;
					ciphopts->decipher_flags[3] = false;

					string sco_errmsg = std::format(
						"\nInvalid single-character option ({:c}) within ({:s}). See HELP with -h or --help option.\n",
						curropt[n],
						curropt
					);
					opt_number = usr_cmdln.size();
					throw std::invalid_argument(sco_errmsg);
				}
			}// end for(n)

			if( valid_sco_used ) {
				opt_number += 1;
			}
			else {
				opt_number = usr_cmdln.size();
				throw std::invalid_argument(ia_errmsg);
			}
		}
		
		curropt.clear();
		curropt.shrink_to_fit();
	}

	return(parse_results);
}

/*
 * Description:
 * Generate the necessary alphabet, punctuation and number mappings to put
 *  into a single map/dictionary for deciphering text.
 *
 * Input:
 * ciphopts -> object containing cipher options/controls
 *
 * Output:
 * None
 */
void generateCipherDict(DecipherCtrlOpts* ciphopts) noexcept
{
	// shift amount for regular uppercase & lowercase alphabet
	ciphopts->reduced_shift_len = calcReducedShift(ciphopts->orig_shift_len);

	// shift amounts for numbers, punctuation, both or neither
	if( ciphopts->dec_numbers ) {
		ciphopts->digits_shift_len = calcReducedShift(
			ciphopts->orig_shift_len, static_cast<int>(ORIG_DIGITS.size()));
	}

	if( ciphopts->dec_puncts ) {
		ciphopts->puncts_shift_len = calcReducedShift(
			ciphopts->orig_shift_len, static_cast<int>(ORIG_PUNCTUATION_SYMBOLS.size()));
	}

	// copies of the character arrays to be circularly shifted
	//   shift arrays as needed and create the final dictionary
	ChrVarr shifted_uppercase = ORIG_UPPERCASE.cshift(ciphopts->reduced_shift_len);
	ChrVarr shifted_lowercase = ORIG_LOWERCASE.cshift(ciphopts->reduced_shift_len);
	ChrVarr shifted_digits    = ORIG_DIGITS.cshift(ciphopts->digits_shift_len);
	ChrVarr shifted_puncts    = ORIG_PUNCTUATION_SYMBOLS.cshift(ciphopts->puncts_shift_len);
	
	for(size_t n = 0; n < shifted_uppercase.size(); ++n) {
		//ciphopts->cipher_dict[ORIG_UPPERCASE[n]] = shifted_uppercase[n];
		ciphopts->cipher_dict[shifted_uppercase[n]] = ORIG_UPPERCASE[n];
	}

	for(size_t n = 0; n < shifted_lowercase.size(); ++n) {
		//ciphopts->cipher_dict[ORIG_LOWERCASE[n]] = shifted_lowercase[n];
		ciphopts->cipher_dict[shifted_lowercase[n]] = ORIG_LOWERCASE[n];
	}

	for(size_t n = 0; n < shifted_digits.size(); ++n) {
		//ciphopts->cipher_dict[ORIG_DIGITS[n]] = shifted_digits[n];
		ciphopts->cipher_dict[shifted_digits[n]] = ORIG_DIGITS[n];
	}

	for(size_t n = 0; n < shifted_puncts.size(); ++n) {
		//ciphopts->cipher_dict[ORIG_PUNCTUATION_SYMBOLS[n]] = shifted_puncts[n];
		ciphopts->cipher_dict[shifted_puncts[n]] = ORIG_PUNCTUATION_SYMBOLS[n];
	}

	return;
}

/*
 * Description:
 * Checks for the existence of the input filename, throws exception if it does not 
 *   exist. If it does exist, reads text (line-by-line) and deciphers the text.
 *   If the output file exists, it is overwritten without asking.
 *
 * Input:
 * ciphopts -> object storing program controls/options
 *
 * Output:
 * None (throws exception for FILE NOT FOUND)
 */
void decipherFileText(DecipherCtrlOpts* ciphopts)
{
	// Form the file pathnames and check for existence
	// Input text file
	fsys::path ifilepath( ciphopts->infilename );
	std::ifstream ifile;

	if( not fsys::exists(ifilepath) ) {
		string errmsg{"Input file not found."};
		std::error_code ec;
		throw fsys::filesystem_error(errmsg,ifilepath,ec);
		return;
	}
	else {
		ifile.open(ifilepath);
	}

	// Output text file
	string fulloname;
	if( ciphopts->use_default_oname ) {
		fulloname = ciphopts->infilename;
		fulloname = fulloname.append(".dec");
		ciphopts->outfilename = fulloname;
	}
	else {
		fulloname = ciphopts->outfilename;
	}

	fsys::path ofilepath( fulloname );

	std::ofstream ofile(ofilepath);

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
	}

	if( ifile.is_open() ) { ifile.close(); }
	if( ofile.is_open() ) { ofile.close(); }

	// Print to screen the number of characters read
	if( not ciphopts->display_log_info ) {
		cout << endl;
		cout << std::format("Read {:d} characters from the input file.", num_chrs_read) << endl;
		cout << endl;
	}
	
	return;
}


/*
 * Description:
 * Prints log-like information to terminal screen.
 *   Information such as name of program, input/output filenames, control 
 *   options, etc.
 *
 * Input:
 * ciphopts -> object containing program control options/values
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
	cerr << "Default output name: " << std::boolalpha << ciphopts->use_default_oname << endl;
	cerr << "Shift amount:        " << ciphopts->orig_shift_len << endl;
	cerr << "[Reduced] Shift:     " << ciphopts->reduced_shift_len << endl;
	cerr << "Shift numbers:       " << std::boolalpha << ciphopts->dec_numbers << endl;
	cerr << "Number shift amount: " << ciphopts->digits_shift_len << endl;
	cerr << "Shift punctuation:   " << std::boolalpha << ciphopts->dec_puncts << endl;
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
