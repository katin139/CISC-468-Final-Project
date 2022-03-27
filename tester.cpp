#include "examples.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <openssl/bn.h>

using namespace std;
using namespace seal;
using namespace std::chrono;


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
    	//cout << endl;
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
    	//cout << "Input vector2: " << endl;
    	//print_vector(input1);
    	
    	vector<double> input2{player2};
    	//cout << "Input vector2: " << endl;
    	//print_vector(input2);
    	
    	Plaintext plain1, plain2, plain_coeff0;
    	double scale = pow(2.0, 30);
    	//print_line(__LINE__);
    	//cout << "Encode input vector1." << endl;
    	encoder.encode(input1, scale, plain1);
 
    	
    	//print_line(__LINE__);
    	//cout << "Encode input vector2." << endl;
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
    	//cout << "Encrypt input vector and add together" << endl;
    	encryptor.encrypt(plain1, encrypted1);
    	encryptor.encrypt(plain2, encrypted2);
    	Ciphertext encrypted_result;
    	evaluator.add(encrypted1, encrypted2, encrypted_result);
    	/*
    	evaluator.add_plain_inplace(encrypted_result, plain_coeff0);
	*/
    	Plaintext plain_result;
    	//print_line(__LINE__);
    	//cout << "Decrypt and decode." << endl;
    	decryptor.decrypt(encrypted_result, plain_result);
    	vector<double> output_result;
    	encoder.decode(plain_result, output_result);
    	//cout << "    + Result vector ...... Correct." << endl;
    	//print_vector(output_result);
    	
	double & winner = output_result[0];
	//cout << "Winner: " << round(winner) << ".\n";
	return round(winner);
	
}

int rsaImplement(int player1, int player2){
	char hex1[20];
	sprintf(hex1,"%X",player1);
	char hex2[20];
	sprintf(hex2,"%X",player2);
	//Initialize all of the variables 
	BN_CTX *ctx1 = BN_CTX_new();
	BIGNUM *res1 = BN_new();
	BIGNUM *y1 = BN_new();
	BN_CTX *ctx2 = BN_CTX_new();
	BIGNUM *res2 = BN_new();
	BIGNUM *y2 = BN_new();
	BIGNUM *m1 = BN_new();
	BIGNUM *m2 = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *ans = BN_new();
	BN_hex2bn(&m1, hex1);
	BN_hex2bn(&m2, hex2);
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&e, "010001");
	
	//Player1 encrypt and decrypt
	//Encrypt the message 
	// m^e mod n
	BN_mod_exp(y1, m1, e, n, ctx1);	
	//Decryt the message 
	// y^d mod n
	BN_mod_exp(res1, y1, d, n, ctx1);
	
	
	//Player2 encrypt and decrypt
	//Encrypt the message 
	// m^e mod n
	BN_mod_exp(y2, m2, e, n, ctx2);
	//Decryt the message 
	// y^d mod n
	BN_mod_exp(res2, y2, d, n, ctx2);

	
	//calculate result
	BN_sub(ans, res2, res1);
	char* ansMay = BN_bn2hex(ans);
	signed int intAns = std::stoul(ansMay, nullptr, 16);
	//cout << "Result: " << intAns << "\n" << endl;

	return intAns;
}

int ckksHelper(){
	string rps;
	string player1val;
	double player2;
	double player1;
	int seed = time(NULL);
	srand(seed);
	int RandIndex = abs((rand()*10) % 3);
	vector<double> choice{-1.0,-2.0,-3.0};
	auto start = high_resolution_clock::now();
	cout << "Here is the CKKS Implementation: " << endl;
	cout << "Enter: rock, paper, or scissors please."<< endl;
	getline (cin, rps);
	cout << "The value you entered is " << rps << "\n";
	if (rps == "rock") {
  		player2 = 1.0;
	} else if (rps == "paper") {
  		player2 = 2.0;
	} else if (rps == "scissors"){
  		player2 = 3.0;
	}
	player1 = choice[RandIndex];
	if (player1 == -1.0) {
  		player1val = "rock";
	} else if (player1 == -2.0) {
  		player1val = "paper";
	} else if (player1 == -3.0){
  		player1val = "scissors";
	}
	cout << "The Computer entered: " << player1val << "\n";
	int result;
	result = ckksImplement(player1, player2);
	if (result==0) {
  		cout << "You tied with the computer. \n"<< endl;
	} else if (result == 1 || result == -2) {
  		cout << "You won!"<< endl;
	} else {
  		cout << "You lost to the computer."<< endl;
	} 
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
	cout << "Time Recorded: " <<  duration.count()/1000 << " milliseconds."<< endl;
	return duration.count()/1000;
}

int rsaHelper(){
	string rps;
	double player2;
	double player1;
	string player1val;
	int seed = time(NULL);
	srand(seed);
	int RandIndex = abs((rand()*10) % 3);
	vector<int> choice{127,128,129};
	auto start = high_resolution_clock::now();
	cout << "Here is the RSA Implementation: " << endl;
	cout << "Enter: rock, paper, or scissors please."<< endl;
	getline (cin, rps);
	
	if (rps == "paper") {
  		player2 = 127;
	} else if (rps == "scissors") {
  		player2 = 128;
	} else if (rps =="rock"){
  		player2 = 129;
	}
	player1 = choice[RandIndex];
	if (player1 == 127) {
  		player1val = "paper";
	} else if (player1 == 128) {
  		player1val = "scissors";
	} else if (player1 == 129){
  		player1val = "rock";
	}
	cout << "You entered:  " << rps <<  "\n";
	cout << "The Computer entered: " << player1val << "\n";
	int result;
	result = rsaImplement(player1, player2);
	
	if (result==0) {
  		cout << "You tied with the computer. \n"<< endl;
	} else if (result == 1 || result == -2) {
  		cout << "You won!"<< endl;
	} else {
  		cout << "You lost to the computer."<< endl;
	} 
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
	cout << "Time Recorded: " <<  duration.count()/1000 << " milliseconds."<< endl;
	return duration.count()/1000;
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
	cout << "We will compare the speed of RSA vs CKKS"<< endl;
	int timeC =ckksHelper();
	cout << "\n"<< endl;
	int timeR = rsaHelper();
	cout << "The time difference between CKKS and RSA: " << timeC-timeR <<" milliseconds."<< endl;
	/*
	getline (cin, rps);
	cout << "The value you entered is " << rps << "\n";
	if(rps == "CKKS" ||rps == "ckks"){
		ckksGUI();
	}else if (rps == "RSA" ||rps == "rsa"){
		rsaGUI();
	}
	*/
}


