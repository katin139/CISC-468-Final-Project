#include "examples.h"

using namespace std;
using namespace seal;


int main()
{
	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(1024);
	SEALContext context(parms);

	cout << "Set encryption parameters and print" << endl;
	print_parameters(context);
}


