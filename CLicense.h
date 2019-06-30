#pragma once
class CLicense
{
private:
	char m_dna[128];
	char m_license[256];
public:
	CLicense(char* dna, char* license);
	~CLicense() {}

	char* DNA() { return m_dna; }
	char* Hash() { return m_license; }
};
