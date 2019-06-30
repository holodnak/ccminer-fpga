#include "CLicense.h"

#include <string.h>

CLicense::CLicense(char* dna, char* license)
{
	strncpy(m_dna, dna, 128);
	strncpy(m_license, license, 256);
}
