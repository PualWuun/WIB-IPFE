#ifndef MASTER_KEY_H
#define MASTER_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <string>

class MasterKey {
    private:
    element_t alpha;
    ElementList *z;

    public:
    MasterKey(int n, pairing_t &pairing);

    element_t *GetAlpha();

    ElementList *GetZ();

    element_t *GetZ_i(int i);
    
    std::string toString();

    ~MasterKey();
};

#endif //MASTER_KEY_H