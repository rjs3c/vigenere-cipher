/**
 * Copyright (C) 2023 Ryan Instrell - All rights reserved.
 *
 * usage: ./vigenere [-h] "message" [-m MODE] [-k "KEY"]
 */

/**
* Provides functions to interact with the i/o streams.
* those used within this program: printf(), fprintf()
*
* https://cplusplus.com/reference/cstdio/
*/
#include <stdio.h>

/**
* Provides functions to interact with strings and arrays.
* those used within this program: strlen(), strncmp()
*
* https://cplusplus.com/reference/cstring/
*/
#include <string.h>

/**
* Provides functions to achieve various activities.
* utilities used within this program: malloc(), EXIT_SUCCESS, EXIT_FAILURE
*
* https://cplusplus.com/reference/cstdlib/
*/
#include <stdlib.h>

/**
* Provides functions to interact with characters.
* those used within this program: isalpha(), isupper(),
* toupper()
*
* https://cplusplus.com/reference/cctype/
*/
#include <ctype.h>

// Constants used repetitively throughout the source code.
/**
 * Defines the modulo space in which the shifts are performed within.
 *
 * This restricts the resulting value within the 0-25 range, this ensuring
 * that the character is alphabetic prior to converting to ASCII.
 */
#define CHAR_SPACE 26

/**
 * After performing the shifts, this value is used to convert the resulting 
 * value into a valid ASCII, alphabetic character. 
 */
#define ASCII_HIGHER_OFFSET 'A'

/**
* 'a' = 'A' ^ 0x20.
*
* This is because the 6th bit of A-Z is always equal to 1, 
* whereas the 6th bit of a-z is always equal to 0. 
* 
* Resultantly, if the 6th bit of an ASCII character is XORed
* with 32 (base 10) / 20 (base 16), this will effectively 
* invert the character's case. 
*/
#define ASCII_LOWER_OFFSET (ASCII_HIGHER_OFFSET ^ 0x20) // 'a'

/**
 * Stores convenient constants to delineate the mode of operation - 
 * that is, encrypt and decrypt.
 *
 * The reason for utilising an enum was because due to the assignment of 
 * integral values to these constants, allowing the easy comparison of the mode.
 *
 * Ex. if(Encrypt) { ... } / if(Decrypt) { ... }
 */
typedef enum modes { Encrypt = 0, Decrypt } modes_t;

/**
 * Stores the type of documentation that will be printed to stdout.
 *
 * The rationale for this is to easily compare, and consequently, present
 * particular information to the user.
 *
 * This is used within the exit_print_info() function, whereby depending on whether
 * the information desired is usage (a short, one-line description) or help 
 * (a complete overview of usage) is required.
 */
typedef enum docs { Help = 0, Usage } docs_t;

/**
 * This structure holds members that are pertinent to the program.
 *
 * A structure was utilised to reduce application complexity, whereby the
 * function prototypes do not contain too many parameters that ultimately 
 * affect readability and maintainability.
 *
 * Without a structure, each of these individual members would require 
 * passing into function parameters. Resultantly, I have grouped these
 * into a cohesive structure.
 *
 * As a result, as opposed to specifying many parameters within function
 * prototypes, I only require one (that is, the config structure). The function
 * can then pick individual members as needed.
 */
typedef struct config {
  modes_t option; // encrypt/decrypt operation.
  char *message; // plain/ciphertext of variable length. 
  char *output; // the resulting output from the encryption/decryption.
  char *key; // the initial key passed in by the user.
  char *keystream; // keystream generated from the supplied key.
} config_t; // within parameters, config_t is the type hint used.

/**
 * This funtion is responsible for printing usage or help information.
 * (try entering a single '-h' parameter or nothing at all).
 *
 * Due to the potential repitition of this functionality, I decided to
 * place this logic within its own function.
 */
static void 
exit_print_info(docs_t type) {
  // Multi-line string literals to hold help (help_str) and usage (usage_str) information.
  const char *usage_str = "usage: ./vigenere [-h] \"message\" [-m MODE] [-k \"KEY\"]\n",
              *help_str = "\npositional arguments: \n\
      message  specifies the message to encrypt/decrypt (A-Z, a-z).\n\
      -m       encrypt/decrypt the subsequent message. \n\
               (0 = encrypt, 1 = decrypt, 0 = default) \n\
      -k       specifies the keyword to use (variable length, ASCII-only). \n\
    \noptional arguments: \n\
      -h       displays help message and usage information.\n\n";

  /**
  * Due to the utilisation of an enum, 
  * the integral values (Help = 0, Usage = 1) can be easily compared.
  */  
  if (type) 

    /**
    * fprintf() prints to a given stream. Given the nature of this
    * message, the output (help/usage message) is being printed to
    * stderr, conversely to stdout.
    * 
    * The default operation of printf() is to print to stdout.
    *
    * https://cplusplus.com/reference/cstdio/fprintf/
    * https://en.cppreference.com/w/cpp/io/c/std_streams
    */
    fprintf(stderr, "%s", usage_str);

    /**
    * At several points within the program conditional statements and their
    * resulting expressions will be placed on the same line.
    * 
    * This is done to save bytes within the file, provided that readibility is not
    * hampered. 
    */
  else fprintf(stderr, "%s%s", usage_str, help_str);

  /**
  * EXIT_FAILURE is a constant as part of stdlib.h.
  * 
  * As opposed to specifying an integer to delineate the exit code,
  * a more easily understandable constant is used. 
  *
  * https://en.cppreference.com/w/c/program/EXIT_status 
  */ 
  exit(EXIT_FAILURE);
}

/**
 * This function is responsible for performing encryption operations.
 *
 * Notice how only the config struct is passed in as a parameter.
 *
 * Furthemore, the config struct is passed in as a reference, so that
 * its members can be modified (notice use of the '->' notation).
 */
static void 
encrypt(config_t *config) {

  /**
  * As the length of the original message is referred to on multiple
  * occasions within this function, I deemed it neccessary to assign
  * this to a constant value of type size_t (simply an unsigned
  * integer). 
  * 
  * By doing this, I can continually refer to this without incurring the
  * runtime penalty of using strlen() repeatedly.
  */ 
  const size_t text_len = strlen(config->message);

  /**
  * The resulting output is allocated on the heap accordingly.
  * 
  * Notably, this allocates the size of the message + 1, as strlen()
  * does not include the NULL terminating value ('\0') within the string.
  */ 
  char *text_enciphered = (char *)malloc(sizeof(char) * text_len + 1);

  /**
  * The encryption is performed on ASCII characters, as this is easily printable, and
  * is significantly more efficient compared to mapping individual characters
  * to a table of integer values.
  * 
  * Futhermore, C allows arithmetic to be easily performed on ASCII values,
  * as these are treated as both integers and characters. 
  */ 
  for (int enc_ctr = 0; enc_ctr <= text_len; enc_ctr++) {

    /**
    * This check is performed to preserve any punctuation within the original message.
    * 
    * If the character is non-alphabetic, simply keep within the enciphered message.
    * 
    * Performed using isalpha() from ctype.h.
    */ 
    if (!isalpha(config->message[enc_ctr])) 
      text_enciphered[enc_ctr] = config->message[enc_ctr];
    else

      /**
      * Equivalent calculation:
      * C[i] = (M[i] + K[i] % 26) + 'A'
      * 
      * M[i] is shifted K[i] places (ASCII values), and if C[i] is not within
      * the alphabetic range (0-25), it will wrap around due to '% 26'.
      * 
      * It is also important to note that the Vigenere cipher uses a 26x26 table,
      * thereby restricting us to the range 0-25.
      */ 
      text_enciphered[enc_ctr] =
        ((toupper(config->message[enc_ctr]) + config->keystream[enc_ctr]) % CHAR_SPACE)
        
        /**
        * + 'A' places the character (uppercase) back within the ASCII character space, as this
        * would otherwise yield non-printable characters. 'a' would have the same effect, but for
        * lowercase characters. This helps preserve case.  
        *
        * Depending on whether the original value in question was uppercase or lowercase,
        * the offset's case is inverted.
        */
        + (isupper(config->message[enc_ctr]) ? ASCII_HIGHER_OFFSET : ASCII_LOWER_OFFSET);
  }

  config->output = text_enciphered;
}

// This function is responsible for performing decryption operations.
static void 
decrypt(config_t *config) {

  /**
  * Once again, as to reduce repetition and, ultimately, repeated computation 
  * of strlen(), this is instead assigned to a constant value. 
  */ 
  const size_t text_len = strlen(config->message);

  /**
  * Similarly to encrypt(), space is allocated on the heap to support the length of 
  * the original message - notably inclusive of the NULL terminator by adding 1
  * to text_len.
  */ 
  char *text_deciphered = (char *)malloc(sizeof(char) * text_len + 1);

  for (int dec_ctr = 0; dec_ctr <= text_len; dec_ctr++) {

    /**
    * Similarly, a check using isalpha() is performed to preserve any
    * punctuation within the original message.
    */
    if (!isalpha(config->message[dec_ctr])) 
      text_deciphered[dec_ctr] = config->message[dec_ctr];
    else

      /**
      * The calculation is slightly different to encrypt(), whereby we must now
      * subtract instead of add.
      *
      * Equivalent calculation:
      * M[i] = ((C[i] - K[i] + 26) % 26) + 'A'
      *
      * In addition, we add 26 to the result of C[i] - K[i] should this be
      * a non-positive number.
      */
      text_deciphered[dec_ctr] = 
        ((toupper(config->message[dec_ctr]) - config->keystream[dec_ctr]) + CHAR_SPACE) % CHAR_SPACE
        // Similarly to encryption, 'A'/'a' is added to convert the value to an alphabetic ASCII value. 
        + (isupper(config->message[dec_ctr]) ? ASCII_HIGHER_OFFSET : ASCII_LOWER_OFFSET);
  }

  config->output = text_deciphered;
}

/**
* This function generates a keystream, given a user-supplied key.
* 
* Following generation of the keystream, this will set the keystream
* member of the config struct - this is why the config struct is passed
* as a reference in the function's parameters.
*/
static void 
generate_keystream(config_t *config) {

  /**
  * To generate a keystream, both the lengths of the supplied key (i.e. KEY = 3)
  * and supplied text must be assigned to constant values using strlen().
  */
  const size_t key_len = strlen(config->key),
              text_len = strlen(config->message);
              
  // Pre-allocate space on the heap to support the keystream of the text's length.
  char *new_keystream = (char *)malloc(sizeof(char) * text_len + 1); // length + 1 to include NULL terminator value ('\0').
  
  /**
  * key_offset is used to support the inclusion of spaces or other non-alphabetic characters,
  *
  * In essence, if M[i] is non-alphabetic, key must remain contiguous and not skip by one.
  * 
  * key_offset is, therefore, taken away so that the keystream remains consistent.
  */
  int key_ctr = 0, key_offset = 0;
  
  for (key_ctr = 0; key_ctr <= text_len && config->message[key_ctr] != '\0'; key_ctr++) {
    if (!isalpha(config->message[key_ctr])) {

      /**
      * If M[i] is non-alphabetic, key_offset is incremented.
      *
      * Following this, i is substracted by key_offset so that K[i] can 
      * continue contiguously.
      */
      new_keystream[key_ctr] = ' ';
      key_offset += 1;

    /**
    * If the key length =/= message length, we require the key to fully pad the message.
    * 
    * To wrap the key (i.e., "KEY") around once the length has been reached, a
    * modulo operation is performed on its index.
    *
    * ex.
    * Message: HELLO WORLD
    * Key: KEY
    * Keystream: KEYKE YKEYK
    */
    } else new_keystream[key_ctr] = toupper(config->key[(key_ctr - key_offset) % key_len]);
  }

  config->keystream = new_keystream;
}

/**
* This function builds the config structure.
*
* This accepts the parameters option, message and key,
* and creates a config struct containing these members
* accordingly.
*
* As per Separation of Concerns (SoC), it was deemed neccessary to divide
* construction of the config structure from the application logic 
* (i.e., within the main() function). 
*/
static config_t
build_config(int option, char *message, char *key) {
  config_t config;

  // Modify members to the values passed in the function parameters.
  config.option = option;
  config.message = message;
  config.key = key;

  return config;
}

/**
* This function parses the command-line arguments passed in by the
* user.
*
* In C, command-line arguments are accessible using argv, which together 
* with argc, are passed into this function to parse into a config structure.
*
* There are alternative means to parsing command-line arguments, including getopt
* (from unistd.h) and argp (argp.h). However, as these are part of the POSIX and
* GNU C libraries, cross-platform compatibility is affected.
*
* Resultantly, this is performed manually. As I have opted to make the command-line
* arguments positional, these are easier to evaluate using the likes of strncmp (
* note: NOT strcmp due to the lack of bounds checking).
* 
* https://www.gnu.org/software/libc/manual/html_node/Program-Arguments.html
*/
static config_t 
parse_args(int argc, char **argv) {

  // Declares two strings which will be assigned to values passed in. 
  char *key, *message;
  modes_t option = Encrypt; // The default mode of operation is to encrypt.
  config_t config; // An instance of the config structure.

  /**
  * Check to identify if the number of arguments supplied (via argc)
  * are expected. For example, here, if no arguments are supplied,
  * the usage information is printed.
  */
  if (argc < 2) exit_print_info(Usage);
  
  // The first positional arguments either denotes help ("-h") or the message itself.
  if (argc > 1 && strncmp(argv[1], "-h", strlen(argv[1])) == 0) 
    exit_print_info(Help);
  else if (strncmp(argv[1], "\0", strlen(argv[1])) == 0) // Check for empty entries. 
    exit_print_info(Usage);
  else message = argv[1];

  // "-m" denotes the mode of operation (that is, encrypt or decrypt).
  if (argc > 3 && strncmp(argv[2], "-m", strlen(argv[2])) == 0)
    if (isdigit(argv[3][0]))
      option = (int)argv[3][0] % 2; // Convert to binary value to support enumeration.
    else exit_print_info(Usage);
  else exit_print_info(Usage);
  
  // "-k" denotes the key - followed by a string expected to assume the key value.
  if (argc > 5 && strncmp(argv[4], "-k", strlen(argv[4])) == 0) 
    key = argv[5];
  else exit_print_info(Usage);

  return build_config(option, message, key); 
}

/**
* The main entry point of the program.
* 
* Here, argc and argv are passed in as arguments, allowing
* users to supply command-line arguments in addition to the compiled
* file. i.e., ./vigenere -h 
*
* This function was written with Separation of Concerns (SoC) in mind,
* with the main function containing as little application logic as 
* needed to function. All other logic is encapsulated within other
* functions.
*/
int 
main(int argc, char **argv) {

  // Passing the command-line arguments into parse_args for further processing.
  config_t config = parse_args(argc, argv);

  /**
  * The config structure is passed in to generate_keystream()
  * as a reference (pass by reference). This allows us, within
  * generate_keystream(), to easily modify the individual
  * members of the config struct.
  *
  * This is passed in using the & notation.
  */
  generate_keystream(&config);
  
  /**
  * As Encrypt and Decrypt are enum constants, these are
  * easily comparable.
  */
  if (config.option == Encrypt)
    encrypt(&config);
  else decrypt(&config);

  // Print the resulting output to stdout.
  printf("%s\n", config.output);

  /**
  * Voluntarily exit successfully using the constant EXIT_SUCCESS,
  * available within stdlib.h.
  */
  return EXIT_SUCCESS;
}
