#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <time.h> // debugging and calculating the amount of time something takes
using namespace std;

const int L = 100;
const int q = 100;
const int x = 2;
int t;
string ciphertext;
char* FILENAME;


const int KEY_RANGE = 25;
const int NUM_FUNCTIONS = 9;

int (* func_arr[NUM_FUNCTIONS])(int); // array consisting of all functions used
map<string, int>* convertFileToMap(ifstream& file); // a map container with all the plaintexts and their indices

/* PROTOTYPES */
int decrypt(string c, map<string, int>* dict);
char forwardShift(char c, int amt);
void debug_getciphertext(int func_num);
void setupFunctionArray();

int modularExp(int base, int expo, int mod);

int main(int argc, char** argv) {
	FILENAME = argv[1];
	ifstream file(FILENAME);
	if (!file) { cerr << "File Not Found!" << endl; return -1; }

	map<string, int>* m = convertFileToMap(file);
	setupFunctionArray();

	/*	This is only used for debugging and used to get ciphertexts from an inputted plaintext.	*/
	// int command;
	// cout << "Enter a command... "; cin >> command;
	// if (command == 1) {
	// 	int func_num;
	// 	cout << "Enter a cipher size... "; cin >> t;
	// 	cout << "Enter a function number... "; cin >> func_num;
	// 	debug_getciphertext(func_num);
	// 	return 1;
	// } else if (command != 0) {
	// 	return 0;
	// }

	cout << "Please enter the t value... ";
	cin >> t;
	cout << "Now please enter the ciphertext... ";
	cin >> ciphertext;

	cout << decrypt(ciphertext, m) << endl;
}


/*	converts the dictionary file to a map,
	storing the plaintext as the index and the number the word is at (q) as the value	*/
map<string, int>* convertFileToMap(ifstream& file) {
	map<string, int>* mymap = new map<string, int>();
	
	int count = 1;
	char line[256];
	while (count <= q && file.getline(line, 256)) {
		int index = ((string) line).find(' ');
		string line_num = ((string) line).substr(0, index);

		istringstream iss(line_num); int i; iss >> i;
		if (i == count) {
			string content = ((string) line).substr(index+1);
			while (content[0] == ' ') content = content.substr(1); // remove spaces at the beginnging of the string
			content = content.substr(0, L);
			mymap->insert(pair<string, int>(content, count));
			count++;
		}
	}

	return mymap;
}

/*	print array function used to print the keys when debugging	*/
void printArray(int* arr, int size) {
	for (int i = 0; i < size; ++i) {
		cout << arr[i] << '\t';
	} cout << endl;
}

/*	shifts a character by a certain amount	*/
char forwardShift(char c, int amt) {
	char ans = (char) c + amt;
	while (!(ans >= 'a' && ans <= 'z')) ans = 'a' + (ans - 'z') - 1;
	return ans;
}

/*	ENCRYPTION SHIFT EQUATIONS	*/
int func0(int i) { // polyalphabetic Vignere shift cipher
	return (i%t);
}
int func1(int i) {
	return (i*L)%t;
}
int func2(int i) {
	return (i+L)%t;
}
int modularExp(int base, int expo, int mod) {
	if (base >= mod) return modularExp(base%mod, expo, mod);

	if (expo == 1) return base%mod;

	if (expo%2 == 0) return modularExp((base*base)%mod, expo/2, mod);
	else return (base * modularExp((base*base)%mod, (expo-1)/2, mod))%mod;
}
int func3(int i) {
	return modularExp(i, L, t);
}
int func4(int i) {
	if (i == 0) return 0; // no shift, since you can't mod zero
	return modularExp(L, i, t);
}
int func5(int i) {
	return modularExp(i, t, t);
}
int func6(int i) {
	if (i == 0) return 0; // no shift, since you can't mod zero
	return modularExp(t, i, t);
}
int func7(int i) {
	return modularExp(t, L, t);
}
int func8(int i) {
	return modularExp(L, t, t);
}
int func9(int i) {
	return (i+L+t)%t;
}
int func10(int i) {
	return (L+t)%t;
}
int func11(int i) {
	return (i+t)%t;
}
int func12(int i) {
	return (i*L*t)%t;
}
int func13(int i) {
	return (L*t)%t;
}
int func14(int i) {
	return (i*t)%t;
}
int func15(int i) {
	return modularExp(i*L, L, t);
}
int func16(int i) {
	return modularExp(i*t, L, t);
}
int func17(int i) {
	return modularExp(L*t, L, t);
}
int func18(int i) {
	if (i == 0) return 0; // no shift, since you can't mod zero
	return modularExp(L*t, i, t);
}
int func19(int i) {
	if (i == 0) return 0; // no shift, since you can't mod zero
	return modularExp(L*i, i, t);
}
int func20(int i) {
	if (i == 0) return 0; // no shift, since you can't mod zero
	return modularExp(i*t, i, t);
}

/*	when given the keys, the dictionary plaintext, the keys, and the function used,
	this function declares whether:
		the plaintext correctly encrypts to the ciphertext,
		the key is wrong at a specific key index, OR
		either the plaintext or the function is wrong (the function does not know)	*/
int functional_decrypt(string word, string c, map<string, int>* dict, int keys[], int function_num) {
	bool mark[t];
	for (int i = 0; i < t; ++i) {
		mark[i] = false;
	}

	string str = "";
	for (int i = 0; i < L; ++i) {
		int index = func_arr[function_num](i);
		char a = forwardShift(word[i], keys[index]);
		if (a == c[i]) {
			mark[index] = true;
			continue;
		}
		else {
			if (mark[index] == false) return index;
			else return -1;
		}
	}
	return t;
}

/*	loops through all dictionary plaintexts, functions, and keys needed
	to declare which plaintext correctly encrypts to the ciphertext */
int decrypt(string c, map<string, int>* dict) {
	if (c.length() != L) return -2;

	for (map<string, int>::iterator it = dict->begin(); it != dict->end(); ++it) {
		int keys[t];
		for (int i = 0; i < t; ++i) {
			keys[i] = 0;
		}

		for (int i = 0; i < NUM_FUNCTIONS; ++i) {
			bool cont_flag = true;
			while (cont_flag) {
				int result = functional_decrypt(it->first, c, dict, keys, i);
				if (result >= 0 && result < t) {
					keys[result]++;
					if (keys[result] >= KEY_RANGE) { // function is wrong
						cont_flag = false;
						break;
					}
					continue; // key is wrong
				} 
				else if (result == -1) {
					cont_flag = false;
					break;
				}
				else if (result == t) return it->second;
			}
		}
	}
	return -1;
}

/*	reads a function, a string, and the keys to get a ciphertext */
void debug_getciphertext(int func_num) {
	int c[t]; string s;
	cout << "Input a string... ";
	cin >> s;

	for (int i = 0; i < t; ++i) {
		cout << "Enter index # " << i << "... "; cin >> c[i];
	}

	string ans = "";
	for (int i = 0; i < s.length(); ++i) { 
		int index = func_arr[func_num](i);
		char a = forwardShift(s[i], c[index]);
		ans += a;
	}
	cout << endl << "Your new string is \n" << ans << endl;
}

/* sets up the function array*/
void setupFunctionArray() {
	func_arr[0] = func0;
	func_arr[1] = func1;
	func_arr[2] = func2;
	func_arr[3] = func3;
	func_arr[4] = func4;
	func_arr[5] = func5;
	func_arr[6] = func6;
	func_arr[7] = func7;
	func_arr[8] = func8;
	func_arr[9] = func9;
	func_arr[10] = func10;
	func_arr[11] = func11;
	func_arr[12] = func12;
	func_arr[13] = func13;
	func_arr[14] = func14;
	func_arr[15] = func15;
	func_arr[16] = func16;
	func_arr[17] = func17;
	func_arr[18] = func18;
	func_arr[19] = func19;
	func_arr[20] = func20;
}