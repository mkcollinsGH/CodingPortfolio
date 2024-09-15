#include <iostream>
#include <fstream>
#include <format>          // formatted strings with variables and specifiers, requires C++20
#include <filesystem>      // file checking, etc. requires C++17 at mininum
#include <stdexcept>       // standard exception std::invalid_argument
#include <string>
#include <valarray>        // for circular-shift functionality
#include <vector>
#include <map>             // act as a dictionary
#include <set>
//#include <unordered_map>
//#include <print>           // formatted file-stream or character-stream printing, requires C++23 

/*
 * TYPES/ALIASES: Aliases and object definitions
 */
namespace fsys = std::filesystem;  // convenience alias

// standard input (keyboard), output (terminal), error (terminal)
using std::cout;
using std::cin;
using std::cerr;
using std::endl;

// standard file stream types (input & output respectively)
using std::ifstream;
using std::ofstream;

 // C++ style string object
using std::string;

typedef std::vector<string> vecstr;
typedef std::valarray<char> varrchr;

typedef std::map<char,char> chrdict;


// object to store user command-line entries and determine overall program
//   functionality
struct CipherOptions 
{ 
	// name of this compiled program as entered on the command-line
	//   and stripped of pathnames preceeding it
	string program_name;
	string prog_name_stripped;

	// input & output filenames
	string infilename;
	string outfilename;
	bool use_default_oname = true;  // an extension (.ciph) will be appended to infilename
	
	// Shift amount entered by user on command-line.
	//   Default cipher shift amount is 5 characters.
	int shift_amount = 5;  

	// calculated after user enters either negative or postive shift_amount
	//   to be strictly positive for modulo arithmetic
	//   Note: modulo arithmetic is used to eliminate unnecessary circular 
	//         shifts of the character maps
	int effective_shift = 5;
	int numbers_shift   = 0;
	int puncts_shift    = 0;

	bool enc_numbers = false;  // encipher numbers from input file
	bool enc_puncts  = false;  // encipher punctation from input file

	// dictionary (C++ map) to encipher alphabet, numbers and punctuation	
	chrdict cipher_dict;

	// number of characters read from the input file (and written to
	//   the output file)
	size_t nbytes_file = 0;

	// flag to show information as the program is running for testing purposes
	bool display_log_info = false;
};


/*
 * CONSTANTS
 */

// uppercase [English] alphabet 
const varrchr ORIG_UPPER = {
	'A','B','C','D','E','F','G','H','I','J',
	'K','L','M','N','O','P','Q','R','S','T',
	'U','V','W','X','Y','Z'
};

// lowercase [English] alphabet 
const varrchr ORIG_LOWER = {
	'a','b','c','d','e','f','g','h','i','j',
	'k','l','m','n','o','p','q','r','s','t',
	'u','v','w','x','y','z'
};

// numbers as characters 
const varrchr ORIG_NUMBERS = {
	'0','1','2','3','4','5','6','7','8','9'
};

// most punctuation as individual characters 
//   placed in ASCII/UTF-8 order
const varrchr ORIG_PUNCTS = {
	'!', '"', '#', '$', '%', '&',
	'\'', '(', ')', '*', '+', ',', 
	'-', '.', '/', ':', ';', '<', 
	'=', '>', '?', '@', '[', '\\',
	']', '^', '_', '`', '{', '|', 
	'}', '~'
}; 


/*
 * FUNCTION DECLARATIONS: Function declarations or definitions if not complex 
 */

/* 
 *   Description: 
 *   Calculates an "effective" shift amount based on whether
 *   the entered shift amount is negative or positive to protect against
 *   unnecessary shifting if the requested shift amount is greater than the
 *   size of the English alphabet
 *
 *   Note:
 *   If this were not a privately-scoped function (meaning it is not defined or 
 *   declared in a header), then mod_size would need to be checked for '0'. 
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
int calculateEffectiveShift(const int& original_shift, const int& mod_size = 26) 
{
	int eff_shift = 0;
	if( original_shift < 0 ) {
		eff_shift = original_shift;
		while( eff_shift < 0 ) {
			eff_shift += mod_size;
		}
	}
	else if( original_shift >= 0 ) {
		eff_shift = original_shift % mod_size;
	}

	return(eff_shift);
}

// Functions to help with command-line or user-interface (terminal-based only)
void printUsage(const string& progname) noexcept;
void printHelp(const string& progname) noexcept;
int parseCommandLine(const vecstr& usrCmdln, CipherOptions* ciphopts);

// create full enciphering dictionary (including alphabet, punctuation, numbers
void generateCipherDict(CipherOptions* ciphopts) noexcept;

// read input file, encipher and write output file
void encipherFileText(CipherOptions* ciphopts);

// Print log-like information to terminal screen
void printLogInfo(CipherOptions* ciphopts) noexcept;


/*
 * MAIN
 */
int main(int nargs, char* args[]) {
	// create storage for raw command-line and converted options/arguments
	vecstr raw_cmdln;
	CipherOptions cmdopts;

	// convert command-line entries to C++ strings and store in vector
	for(int n = 0; n < nargs; ++n) {
		raw_cmdln.push_back(string(args[n]));
	}

	try
	{
		// can throw an std::invalid_argument exception
		int parse_res = parseCommandLine(raw_cmdln, &cmdopts);

		if( parse_res == 1 ) {
			// user either needed USAGE or HELP printed
			return(0);
		}
		else if( parse_res == 0 ) {
			generateCipherDict(&cmdopts);

			// can throw a filesystem_error exception
			encipherFileText(&cmdopts);

			// print log-like info
			if( cmdopts.display_log_info ) {
				printLogInfo(&cmdopts);
			}
		}// end if-elseif(parse_res)
	}
	catch( const std::invalid_argument& e) {
		cout << e.what() << endl;
		return(1);
	}
	catch( const fsys::filesystem_error& e ) {
		cout << e.what() << endl;
		return(1);
	}
	catch( ... ) {
		// general catch-all error-handling
		cout << "Unexpected error encountered. Program terminated." << endl;
		return(1);
	}

	// exit successfully
	return(0);
}

/*
 * FUNCTION DEFINITIONS: Function defintions if long or complex
 */

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
void printUsage(const string& progname) noexcept
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
void printHelp(const string& progname) noexcept
{
	cout << endl;
	cout << "Usage:" << endl;
	cout << progname << " [options]";
	cout << " -i <IFILE> [-o <OFILE>]" << endl;
	cout << endl;
	cout << "Required:" << endl;
	cout << "  -i, --ifile <IFILE>       ";
	cout << " \tName of input file to read (must be ASCII or UTF text)" << endl;
	cout << endl;
	cout << "Options:" << endl;
	cout << "  -o, --ofile <OFILE>       ";
	cout << " \tName of output file to write (will be overwritten if exists)" << endl;
	cout << "                            ";
	cout << " \tDefault filename created by appending \".ciph\" to IFILE if option not used" << endl;
	cout << endl;
	cout << "  -s, --shift-amount <SHIFT>";
	cout << " \tNumber of characters to shift alphabet (default: 5)" << endl;
	cout << endl;
	cout << "  -n, --shift-nums          ";
	cout << " \tInclude numbers in shifted/enciphered alphabet (default: false)" << endl;
	cout << endl;
	cout << "  -p, --shift-puncts        ";
	cout << " \tInclude punctuation in shifted/enciphered alphabet (default: false)" << endl;
	cout << "  -a, --shift-all           ";
	cout << " \tShift both numbers and punctuation (default: false)" << endl;
	cout << "  -h, --help                ";
	cout << " \tPrint HELP message and stop without processing" << endl;
	cout << endl;
	return;
}

/*
 * Description:
 * Parses user-entered command-line for proper options or HELP. Throws a
 *  std::invalid_argument exception if an improper option is found in the 
 *  entered command-line.
 *  Handles stripping of program name to name-only instead of full path.
 *
 * Input:
 * usr_cmdln -> user-entered command-line as C++ style strings
 * ciphopts  -> pointer to object to hold results of parsed/evaluated options
 *
 * Output:
 * Integer to indicate successful parsing/evaluation or HELP message requested
 */
int parseCommandLine(const vecstr& usr_cmdln, CipherOptions* ciphopts)
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
			ciphopts->shift_amount = std::stoi(currarg, nullptr, 10);
			opt_number += 2;
		}
		else if( (curropt.compare("--shift-nums") == 0) ) 
		{
			ciphopts->enc_numbers = true;
			opt_number += 1;
		}
		else if( (curropt.compare("--shift-puncts") == 0) ) 
		{
			ciphopts->enc_puncts = true;
			opt_number += 1;
		}
		else if( (curropt.compare("--shift-all") == 0) ) 
		{
			ciphopts->enc_numbers = true;
			ciphopts->enc_puncts  = true;
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
							ciphopts->enc_numbers = true;
							ciphopts->enc_puncts  = true;
							break;
						case 'n':
							ciphopts->enc_numbers = true;
							break;
						case 'p':
							ciphopts->enc_puncts = true;
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
					ciphopts->enc_numbers = false;
					ciphopts->enc_puncts = false;

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
 *  into a single map/dictionary for enciphering text.
 *
 * Input:
 * ciphopts -> object containing cipher options/controls
 *
 * Output:
 * None
 */
void generateCipherDict(CipherOptions* ciphopts) noexcept
{
	// shift amount for regular uppercase & lowercase alphabet
	ciphopts->effective_shift = calculateEffectiveShift(ciphopts->shift_amount);

	// shift amounts for numbers, punctuation, both or neither
	if( ciphopts->enc_numbers ) {
		ciphopts->numbers_shift = calculateEffectiveShift(
			ciphopts->shift_amount, static_cast<int>(ORIG_NUMBERS.size()));
	}

	if( ciphopts->enc_puncts ) {
		ciphopts->puncts_shift = calculateEffectiveShift(
			ciphopts->shift_amount, static_cast<int>(ORIG_PUNCTS.size()));
	}

	// copies of the character arrays to be circularly shifted
	//   shift arrays as needed and create the final dictionary
	varrchr shifted_upper   = ORIG_UPPER.cshift(ciphopts->effective_shift);
	varrchr shifted_lower   = ORIG_LOWER.cshift(ciphopts->effective_shift);
	varrchr shifted_numbers = ORIG_NUMBERS.cshift(ciphopts->numbers_shift);
	varrchr shifted_puncts  = ORIG_PUNCTS.cshift(ciphopts->puncts_shift);
	
	for(size_t n = 0; n < shifted_upper.size(); ++n) {
		ciphopts->cipher_dict[ORIG_UPPER[n]] = shifted_upper[n];
	}

	for(size_t n = 0; n < shifted_lower.size(); ++n) {
		ciphopts->cipher_dict[ORIG_LOWER[n]] = shifted_lower[n];
	}

	for(size_t n = 0; n < shifted_numbers.size(); ++n) {
		ciphopts->cipher_dict[ORIG_NUMBERS[n]] = shifted_numbers[n];
	}

	for(size_t n = 0; n < shifted_puncts.size(); ++n) {
		ciphopts->cipher_dict[ORIG_PUNCTS[n]] = shifted_puncts[n];
	}

	return;
}

/*
 * Description:
 * Checks for the existence of the input filename, throws exception if it does not 
 *   exist. If it does exist, reads text (line-by-line) and enciphers the text.
 *   If the output file exists, it is overwritten without asking.
 *
 * Input:
 * ciphopts -> object storing program controls/options
 *
 * Output:
 * None (throws exception for FILE NOT FOUND)
 */
void encipherFileText(CipherOptions* ciphopts)
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
		fulloname = fulloname.append(".ciph");
	}
	else {
		fulloname = ciphopts->outfilename;
	}

	fsys::path ofilepath( fulloname );

	std::ofstream ofile(ofilepath);

	// Read input stream and write enciphered output stream
	
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
void printLogInfo(CipherOptions* ciphopts) noexcept 
{
	cout << endl;
	cout << "==============================" << endl;
	cout << "Cipher program options/control" << endl;
	cout << "==============================" << endl;
	cout << "[Raw] Program name:  " << ciphopts->program_name << endl;
	cout << "[Stripped] Name:     " << ciphopts->prog_name_stripped << endl;
	cout << "IFILE:               " << ciphopts->infilename << endl;
	cout << "OFILE:               " << ciphopts->outfilename << endl;
	cout << "Default output name: " << (ciphopts->use_default_oname ? "true" : "false") << endl;
	cout << "Shift amount:        " << ciphopts->shift_amount << endl;
	cout << "[Effective] Shift:   " << ciphopts->effective_shift << endl;
	cout << "Shift numbers:       " << (ciphopts->enc_numbers ? "true" : "false") << endl;
	cout << "Number shift amount: " << ciphopts->numbers_shift << endl;
	cout << "Shift punctuation:   " << (ciphopts->enc_puncts ? "true" : "false") << endl;
	cout << "Punct. shift amount: " << ciphopts->puncts_shift << endl;
	cout << "Encipher dictionary: {";
	auto dIter = ciphopts->cipher_dict.find('A');
	for(size_t n = 0; n < 10; ++n, std::advance(dIter,1)) 
	{
		cout << "(" << std::get<0>(*dIter) << "," << std::get<1>(*dIter) << "), ";
	}
	cout << "...}" << endl;
	cout << "Number chars read:   " << ciphopts->nbytes_file << endl;
	cout << "==============================" << endl;
	cout << endl;
	
	return;
}

