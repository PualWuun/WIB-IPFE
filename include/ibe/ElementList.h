#ifndef ELEMENT_LIST_H
#define ELEMENT_LIST_H

#include <pbc/pbc.h>
#include <vector>
#include <string>

class ElementList {
    private:
    std::vector<element_t *> data;
    int offset = 0;

    public:
    ElementList();

    explicit ElementList(int n, int offset, element_t &type, bool randomit);

    explicit ElementList(ElementList *target, int offset);

    explicit ElementList(ElementList *target, int totlen, int offset, bool randomit);

    void resize(int n);

    void SetOffset(int offset);

    int GetOffset();

    int len();

    void add(element_t &x);

    void remove_front();

    void remove_front_at(int i);

    bool operator!=(const ElementList &b);

    element_t *At(int i);

    std::string hash();
    
    std::string toString(std::string lenname, std::string name);

    ~ElementList();
};

#endif //ELEMENT_LIST_H