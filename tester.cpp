#include "examples.h"
#include <stdio.h>
#include <openssl/bn.h>

using namespace std;
using namespace seal;


int ckksImplement(double player1, double player2)
{
	/*
	Start by setting up the CKKS scheme
	*/
	EncryptionParameters parms(scheme_type::ckks);
	/*
	Set the parameter values
	*/
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
    	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));
    	
    	SEALContext context(parms);
    	//print_parameters(context);
    	cout << endl;
    	/*
	Set the keys
	*/
    	KeyGenerator keygen(context);
    	auto secret_key = keygen.secret_key();
    	PublicKey public_key;
    	keygen.create_public_key(public_key);
    	RelinKeys relin_keys;
    	keygen.create_relin_keys(relin_keys);
    	/*
	Set up encryptor & decryptor
	*/
    	Encryptor encryptor(context, public_key);
    	Evaluator evaluator(context);
    	Decryptor decryptor(context, secret_key);
    	
    	CKKSEncoder encoder(context);
    	
    	size_t slot_count = encoder.slot_count();
    	//cout << "Number of slots: " << slot_count << endl;
    	
    	vector<double> input1{player1};
    	cout << "Input vector2: " << endl;
    	print_vector(input1);
    	
    	vector<double> input2{player2};
    	cout << "Input vector2: " << endl;
    	print_vector(input2);
    	
    	Plaintext plain1, plain2, plain_coeff0;
    	double scale = pow(2.0, 30);
    	print_line(__LINE__);
    	cout << "Encode input vector1." << endl;
    	encoder.encode(input1, scale, plain1);
 
    	
    	print_line(__LINE__);
    	cout << "Encode input vector2." << endl;
    	encoder.encode(input2, scale, plain2);
    	encoder.encode(1.0, scale, plain_coeff0);
    	
    	vector<double> output1;
    	//cout << "    + Decode input vector1 ...... Correct." << endl;
    	encoder.decode(plain1, output1);
    	//print_vector(output1);
    	
    	vector<double> output2;
    	//cout << "    + Decode input vector2 ...... Correct." << endl;
    	encoder.decode(plain2, output2);
    	//print_vector(output2);
    	
    	
    	Ciphertext encrypted1;
    	Ciphertext encrypted2;
    	
    	//print_line(__LINE__);
    	cout << "Encrypt input vector and add together" << endl;
    	encryptor.encrypt(plain1, encrypted1);
    	encryptor.encrypt(plain2, encrypted2);
    	Ciphertext encrypted_result;
    	evaluator.add(encrypted1, encrypted2, encrypted_result);
    	/*
    	evaluator.add_plain_inplace(encrypted_result, plain_coeff0);
	*/
    	Plaintext plain_result;
    	//print_line(__LINE__);
    	cout << "Decrypt and decode." << endl;
    	decryptor.decrypt(encrypted_result, plain_result);
    	vector<double> output_result;
    	encoder.decode(plain_result, output_result);
    	//cout << "    + Result vector ...... Correct." << endl;
    	//print_vector(output_result);
    	
	double & winner = output_result[0];
	cout << "Winner: " << round(winner) << ".\n";
	return round(winner);
	
}

void printBN(char *msg, BIGNUM * a){
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int rsaImplement(){
	int a = 128;
	char hex[20];
	sprintf(hex,"%X",a);
	//Initialize all of the variables 
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *res = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	BN_hex2bn(&m, hex);
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	
	printBN("m = ", m);
	/*
	//Encrypt the message 
	// m^e mod n
	BN_mod_exp(y, m, e, n, ctx);
	printBN("y = ", y);

	//Decryt the message 
	// y^d mod n
	BN_mod_exp(res, y, d, n, ctx);
	printBN("x = ", res);

	//Reprint the plaintext message
	printBN("M = ", m);
	*/
	return 0;
}

int main(){

	string rps;
	double player2;
	double player1;
	int seed = time(NULL);
	srand(seed);
	int RandIndex = (rand()*10) % 3;
	vector<double> choice{-1.0,-2.0,-3.0};
	cout << "Here is a game of rock, paper, scissors! " << endl;
	cout << "You can choose RSA or CKKS encryption: "<< endl;
	getline (cin, rps);
	cout << "The value you entered is " << rps << "\n";
	if(rps == "CKKS"){
		cout << "Here is the CKKS Implementation: " << endl;
	cout << "We will play a game of rock, paper, scissors. "<< endl;
	cout << "You will play against the computer!"<< endl;
	cout << "Enter: rock, paper, or scissors please."<< endl;
	getline (cin, rps);
	cout << "The value you entered is " << rps << "\n";
	if (rps == "rock") {
  		player2 = 1.0;
	} else if (rps == "paper") {
  		player2 = 2.0;
	} else {
  		player2 = 3.0;
	}
	player1 = choice[RandIndex];
	cout << "The value comp entered is " << player1 << "\n";
	int result;
	result = ckksImplement(player1, player2);
	if (result == 0) {
  		cout << "You tied with the computer. \n"<< endl;
	} else if (result == 1) {
  		cout << "You won!"<< endl;
	} else {
  		cout << "You lost to the computer."<< endl;
	}
	}else{
		cout << "You chose RSA \n";
		rsaImplement();
	}

}


