#include "CLicenseDB.h"

/*

License Database structure:

The license generator outputs format "<dna> = <hash>" and does not include any id's for
the algorithm or userdata bytes.  So in order for multiple licenses to stay in the same
directory, we must keep a database of all the licenses belonging to a specific DNA then
we must try all of the licenses on the FPGA and see if any of them unlock it.

*/


CLicenseDB::CLicenseDB()
{
}


CLicenseDB::~CLicenseDB()
{
}
