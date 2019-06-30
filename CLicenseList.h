#pragma once

struct license_entry_s {
	char hash[256];
	struct license_entry_s* next;
};

class CLicenseList
{
private:
	char m_dna[64];
	struct license_entry_s* m_hashes;
public:
	CLicenseList();
	~CLicenseList();
};
