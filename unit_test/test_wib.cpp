#include <iostream>
#include <pbc/pbc.h>
#include <chrono>
#include "ibe/HIDparam.h"
#include <sys/stat.h>
#include <cstring>

#define DO_WIB

int n = 5, d = 6, bstep = 50, max_res = 100 * bstep;
int ITS = 50;
FILE *out = NULL;

std::vector<int> id_pattern_sizes = {10, 50, 100, 150, 200};
std::vector<std::pair<int, int>> nd_list;

std::vector<int> x_vec = {3, 2, 1, 2, 1, 3, 2, 1, 2, 1, 3, 2, 1, 2, 1, 3, 2, 1, 2, 1};
std::vector<int> y_vec = {11, 22, 33, 22, 33, 11, 22, 33, 22, 33, 11, 22, 33, 22, 33, 11, 22, 33, 22, 33};

std::chrono::_V2::system_clock::time_point setup_s, setup_e, keygen_s, keygen_e, delegate_s, delegate_e, enc_s, enc_e, dec_s, dec_e;

int ips = 5;

int redata = 0;

const std::string diver = "-----------------------------------";

const bool out_file = true, visiable = false;

void OutTime(std::string name, int id, double us)
{
    us /= 1000;
    if (out_file)
        fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if (visiable)
        printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

void tqdm(std::string name, int now, int total)
{
    if (!visiable)
        return;
    int pers = now * 100 / total;
    printf("\r");
    printf("%s: [", name.c_str());
    for (int i = 0; i < pers / 2 - 1; i++)
        printf("=");
    printf(">");
    for (int i = 0; i < 50 - 1 - pers / 2; i++)
        printf(" ");
    printf("] %d%%", pers);
    for (int i = 0; i < 50; i++)
        printf(" ");
}

char DIVIDER[] = "--------------------------------------------------------------------------------";

#ifdef DO_WIB
#include "schemes/wib_pk_ipfe.h"
WIB_PK_IPFE *test_wib = NULL;
void CountTime(WIB_PK_IPFE &test, int level, int iter_times = ITS)
{
    // std::vector<int> id_pattern_sizes = {10, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500};
    PublicKeyWIB *PK = NULL;
    SecretKeyWIB *SK = NULL;
    SecretKeyWIB *SK1 = NULL, *SK2 = NULL;
    CipherTextWIB *CT = NULL;
    element_t *res = NULL, *ID1ips = NULL;
    ElementList *x = NULL, *y = NULL, *P1 = NULL, *P2 = NULL;
    HIDparamWIB *P1param = NULL, *P2param = NULL;
    if (iter_times != 1)
        if (visiable)
            printf("\e[s");

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    for (std::pair<int, int> tmp : nd_list)
    {
        n = tmp.first;
        d = tmp.second;
        if (out_file)
            fprintf(out, "l: %d, n: %d, d: %d\n", ips, n, d);
        if (visiable)
            printf("\e[u");
        if (visiable)
            printf("now l: %d, n: %d, d: %d                               \n", ips, n, d);

        for (int i = 0; i < iter_times; ++i)
        {
            tqdm("setup", i + 1, iter_times);
            test.cleanSetUp();
            setup_s = std::chrono::high_resolution_clock::now();
            PK = test.Setup(n, d);
            setup_e = std::chrono::high_resolution_clock::now();
            if (level == 1 || (iter_times == 1 && redata == 0))
                OutTime("setup", i, time_cast(setup_e, setup_s));
            else
                break;
        }

        if (level > 1)
        {
            if (x != NULL)
                delete x;
            x = test.I2Zp(x_vec, true);
            if (y != NULL)
                delete y;
            y = test.I2Zp(y_vec, true);

            if (P1 != NULL)
                delete P1;
            P1 = test.GenZnList(ips);
            if(P1param != NULL) delete P1param;
            P1param = new HIDparamWIB(P1, PK->GetU(), PK->GetH(), PK->GetC(), PK->GetG(), PK->GetG_1());
            ID1ips = P1->At(ips);

            if (P2 != NULL)
                delete P2;
            P2 = new ElementList(P1, ips, 0, false);
            P2param = new HIDparamWIB(P2, PK->GetU(), PK->GetH(), PK->GetC(), PK->GetG(), PK->GetG_1());

            for (int i = 0; i < iter_times; ++i)
            {
                tqdm("keygen", i + 1, iter_times);
                if (SK != NULL)
                    delete SK;
                keygen_s = std::chrono::high_resolution_clock::now();
                SK = test.KeyGen(P1, y,P1param);
                keygen_e = std::chrono::high_resolution_clock::now();
                if (level == 2 || (iter_times == 1 && redata == 0))
                    OutTime("keygen", i, time_cast(keygen_e, keygen_s));
                else
                    break;
            }

            if (level > 2)
            {
                if (level == 3 || (iter_times == 1 && redata == 0))
                {
                    if (SK1 != NULL)
                        delete SK1;
                    SK1 = test.KeyGen(P2, y, P2param);
                    for (int i = 0; i < iter_times; ++i)
                    {
                        tqdm("delegate", i + 1, iter_times);
                        if (SK2 != NULL)
                            delete SK2;
                        delegate_s = std::chrono::high_resolution_clock::now();
                        SK2 = test.Delegate(SK1, P2, P2param);
                        delegate_e = std::chrono::high_resolution_clock::now();
                        OutTime("delegate", i, time_cast(delegate_e, delegate_s));
                    }
                }

                if (level > 3)
                {
                    for (int i = 0; i < iter_times; ++i)
                    {
                        tqdm("encrypt", i + 1, iter_times);
                        if (CT != NULL)
                            delete CT;
                        enc_s = std::chrono::high_resolution_clock::now();
                        CT = test.Encrypt(P1, x,P1param);
                        enc_e = std::chrono::high_resolution_clock::now();
                        if (level == 4 || (iter_times == 1 && redata == 0))
                            OutTime("encrypt", i, time_cast(enc_e, enc_s));
                        else
                            break;
                    }

                    if (level > 4)
                    {
                        test.init_dlog(bstep);
                        test.init_max_res(max_res);

                        for (int i = 0; i < iter_times; ++i)
                        {
                            tqdm("decrypt", i + 1, iter_times);
                            if (res != NULL)
                                element_clear(*res);
                            dec_s = std::chrono::high_resolution_clock::now();
                            res = test.Decrypt(CT, SK);
                            dec_e = std::chrono::high_resolution_clock::now();
                            if (level == 5 || (iter_times == 1 && redata == 0))
                                OutTime("decrypt", i, time_cast(dec_e, dec_s));
                            else
                                break;
                        }
                    }
                }
            }
        }
        if (out_file)
            fprintf(out, "-----------------------------------\n");
        if (visiable)
            printf("\n");
    }
#undef time_cast
    if (SK != NULL)
        delete SK;
    if (SK1 != NULL)
        delete SK1;
    if (SK2 != NULL)
        delete SK2;
    if (CT != NULL)
        delete CT;
    if (res != NULL)
        element_clear(*res);
    if (x != NULL)
        delete x;
    if (y != NULL)
        delete y;
    if (P1 != NULL)
        delete P1;
    if (P2 != NULL)
        delete P2;
}
bool CheckDecrypt(WIB_PK_IPFE &test, bool output = false)
{
    printf("%s\n", DIVIDER);
    printf("测试加解密功能\n\n");
    int l = 5;
    n = l;
    d = l;

    PublicKeyWIB *test_PK = test.Setup(n, d); // 获得PK
    if (output)
        printf("%s\n\n", test_PK->toString().c_str());

    ElementList *x = test.I2Zp(std::vector<int>{1, 2, 3}, true);
    if (output)
        printf("%s\n\n", x->toString("n", "x").c_str());

    ElementList *y = test.I2Zp(std::vector<int>{0, 1, 0}, true);
    if (output)
        printf("%s\n\n", y->toString("n", "y").c_str());

    ElementList *P = test.GenZnList(l);
    if (output)
        printf("%s\n\n", P->toString("l", "P").c_str());
    HIDparamWIB *Pparam = new HIDparamWIB(P, test_PK->GetU(), test_PK->GetH(), test_PK->GetC(), test_PK->GetG(), test_PK->GetG_1());

    CipherTextWIB *CT = test.Encrypt(P, x, Pparam);
    if (output)
        printf("%s\n\n", CT->toString().c_str());

    SecretKeyWIB *SK = test.KeyGen(P, y, Pparam); // 使用HID和y生成SK
    if (output)
        printf("%s\n\n", SK->toString().c_str());

    element_t *xy = test.Decrypt(CT, SK); // 计算内积

    printf("%s\n", DIVIDER);

    delete x;
    delete y;
    delete P;
    // delete CT;
    delete SK;

    if (xy != NULL)
    {
        element_clear(*xy);
        printf("测试通过!\n");
        return true;
    }
    else
    {
        printf("测试未通过!\n");
        return false;
    }
}
bool CheckDelegrate(WIB_PK_IPFE &test, bool output = false)
{
    printf("%s\n", DIVIDER);
    printf("测试Delegate功能\n");
    int l = 5;
    n = l;
    d = l;

    bool tag = true;

    PublicKeyWIB *test_PK = test.Setup(5, 10); // 获得PK
    if (output)
        printf("%s\n\n", test_PK->toString().c_str());

    ElementList *x = test.I2Zp(std::vector<int>{1, 2, 3}, true);
    if (output)
        printf("%s\n\n", x->toString("n", "x").c_str());

    ElementList *y = test.I2Zp(std::vector<int>{0, 1, 0}, true);
    if (output)
        printf("%s\n\n", y->toString("n", "y").c_str());

    ElementList *P1 = test.GenZnList(l);
    HIDparamWIB *P1param = new HIDparamWIB(P1, test_PK->GetU(), test_PK->GetH(), test_PK->GetC(), test_PK->GetG(), test_PK->GetG_1());
    if (output)
        printf("%s\n\n", P1->toString("n", "P1").c_str());

    ElementList *P2 = new ElementList(P1, l, 0, false);
    HIDparamWIB *P2param = new HIDparamWIB(P2, test_PK->GetU(), test_PK->GetH(), test_PK->GetC(), test_PK->GetG(), test_PK->GetG_1());
    if (output)
        printf("%s\n\n", P2->toString("n", "P2").c_str());

    CipherTextWIB *CT1 = test.Encrypt(P1, x, P1param); // 使用HID1和x生成CT1
    if (output)
        printf("%s\n\n", CT1->toString().c_str());

    SecretKeyWIB *SK1 = test.KeyGen(P2, y, P2param); // 使用HID2和y生成SK1
    if (output)
        printf("SK1: %s\n\n", SK1->toString().c_str());

    SecretKeyWIB *SK2 = test.KeyGen(P1, y, P1param); // 使用HID1和y生成SK2
    if (output)
        printf("SK2: %s\n\n", SK2->toString().c_str());

    SecretKeyWIB *SK1_P = test.Delegate(SK1, P2, P1param); // SK1 delegate 成为 HID1
    if (output)
        printf("%s\n", SK1_P->toString().c_str());

    if (output)
        printf("%s\n%s\n", x->toString("n", "x").c_str(), y->toString("n", "y").c_str());
    element_t *xy1 = test.Decrypt(CT1, SK1); // 计算内积
    if (output)
        printf("计算Decrypt(CT1, SK1)\n");
    if (xy1 != NULL)
        element_clear(*xy1);
    else
        tag = false;

    element_t *xy2 = test.Decrypt(CT1, SK1_P); // 计算内积
    if (output)
        printf("计算Decrypt(CT1, SK1_P)\n");
    if (xy2 != NULL)
        element_clear(*xy2);
    else
        tag = false;

    element_t *xy3 = test.Decrypt(CT1, SK2); // 计算内积
    if (output)
        printf("计算Decrypt(CT1, SK2)\n");
    if (xy3 != NULL)
        element_clear(*xy3);
    else
        tag = false;
    printf("%s\n", DIVIDER);
    delete x;
    delete y;
    delete P1;
    delete P2;
    // delete CT1;
    delete SK1;
    delete SK2;
    delete SK1_P;
    return tag;
}
#endif

CurveParams curves;

template <typename T>
bool Check(T test, bool debug = false)
{
    return CheckDecrypt(test, debug) && CheckDelegrate(test, debug);
}

void c
()
{
    nd_list.clear();
    for (n = 10; n <= 15; n++)
        for (d = 10; d <= 15; d++)
            nd_list.push_back(std::make_pair(n, d));
    d = 20;
    for (n = 10; n <= 150; n += 10)
        nd_list.push_back(std::make_pair(n, d));
    n = 10;
    for (d = 5; d <= 20; d++)
        nd_list.push_back(std::make_pair(n, d));
    // for(d = 5;d <= 5;d++) nd_list.push_back(std::make_pair(n, d));
}

int main(int argc, char *argv[])
{
    // ndParam();
    if (argc < 7)
        return 0;

    nd_list.clear();
    n = atoi(argv[1]);
    d = atoi(argv[2]);
    nd_list.push_back(std::make_pair(n, d));
    int scheme = -1, curve_id = -1, is_first = atoi(argv[5]), level = -1;

    if (argc >= 8)
        ITS = atoi(argv[7]);
    if (argc >= 9)
        redata = atoi(argv[8]);

    if (strcmp(argv[3], "wib") == 0)
    {
        scheme = 3;
        test_wib = new WIB_PK_IPFE();
    }

    if (strcmp(argv[4], "a") == 0)
        curve_id = 1;
    else if (strcmp(argv[4], "a1") == 0)
        curve_id = 2;
    else if (strcmp(argv[4], "e") == 0)
        curve_id = 3;

    if (strcmp(argv[6], "setup") == 0)
        level = 1;
    else if (strcmp(argv[6], "keygen") == 0)
        level = 2;
    else if (strcmp(argv[6], "delegate") == 0)
        level = 3;
    else if (strcmp(argv[6], "encrypt") == 0)
        level = 4;
    else if (strcmp(argv[6], "decrypt") == 0)
        level = 5;

    if (curve_id == 1)
    {
        if (scheme == 3)
        {
            test_wib->change_type(curves.a_param);
            if (is_first == 0)
            {
                if (out_file)
                    out = fopen("tmp.txt", "w");
                if (visiable)
                    printf("%s\n开始测试type a\n", diver.c_str());
                CountTime(*test_wib, level);
                if (out_file)
                    fclose(out);
            }
            else if (is_first == 1)
            {
                if (out_file)
                    out = fopen("tmp_first.txt", "w");
                if (visiable)
                    printf("\e[s");
                for (int i = 0; i < ITS; i++)
                    CountTime(*test_wib, level, 1);
                if (out_file)
                    fclose(out);
            }
        }
    }
    else if (curve_id == 2)
    {
        if (scheme == 3)
        {
            test_wib->change_type(curves.a1_param);
            if (is_first == 0)
            {
                if (out_file)
                    out = fopen("tmp.txt", "w");
                if (visiable)
                    printf("%s\n开始测试type a1\n", diver.c_str());
                CountTime(*test_wib, level);
                if (out_file)
                    fclose(out);
            }
            else if (is_first == 1)
            {
                if (out_file)
                    out = fopen("tmp_first.txt", "w");
                if (visiable)
                    printf("\e[s");
                for (int i = 0; i < ITS; i++)
                    CountTime(*test_wib, level, 1);
                if (out_file)
                    fclose(out);
            }
        }
    }
    else if (curve_id == 3)
    {
        if (scheme == 3)
        {
            test_wib->change_type(curves.e_param);
            if (is_first == 0)
            {
                if (out_file)
                    out = fopen("tmp.txt", "w");
                if (visiable)
                    printf("%s\n开始测试type e\n", diver.c_str());
                CountTime(*test_wib, level);
                if (out_file)
                    fclose(out);
            }
            else if (is_first == 1)
            {
                if (out_file)
                    out = fopen("tmp_first.txt", "w");
                if (visiable)
                    printf("\e[s");
                for (int i = 0; i < ITS; i++)
                    CountTime(*test_wib, level, 1);
                if (out_file)
                    fclose(out);
            }
        }
    }

    return 0;
}