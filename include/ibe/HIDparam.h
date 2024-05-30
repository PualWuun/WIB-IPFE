#ifndef ELEMENT_HID_PARAM_H
#define ELEMENT_HID_PARAM_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>

class HIDparamWIB {
    private:
    ElementList *u_i_h_i_c, *u_i_h_i_c_Pi;
    element_t g_1_g_c, u_i_h_i_c_times;
    public:
    HIDparamWIB(ElementList *P, ElementList *u_i, ElementList *h_i, element_t *c, element_t *g, element_t *g_1);

    element_t *GetG_1_G_C();

    element_t *GetU_i_H_i_C_Times();

    element_t *GetU_i_H_i_C(int i);

    element_t *GetU_i_H_i_C_P_i(int i);

    ~HIDparamWIB();
};

class HIDparam {
    private:
    ElementList *u_i_h_i, *u_i_h_i_ID_i;
    element_t g_1_g_ID_1, u_i_h_i_ID_i_times;
    public:
    HIDparam(ElementList *ID, ElementList *u_i, ElementList *h_i, element_t *g, element_t *g_1);

    element_t *GetG_1_G_ID_1();

    element_t *GetU_i_H_i_ID_i_Times();

    element_t *GetU_i_H_i(int i);

    element_t *GetU_i_H_i_ID_i(int i);

    ~HIDparam();
};

#endif //ELEMENT_HID_PARAM_H