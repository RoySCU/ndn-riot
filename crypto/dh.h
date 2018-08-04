#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>

#define MAX 500 
#define NUMP 2 
#define NUMG 50 

char p_set[NUMP][110]=
{
    {"3383489120380959248493525538580021146558530486980451874557556432721233835930146323754645777760514961"},
    {"3383489120380959248493525538580021146558530486980451874557556432721233835930146323754645777760514963"}
};

//if you don't know how to use it, please refer to https://download.csdn.net/download/wzcyy2121/10186566
//account and password: Birldlee 19001900aA,

int get_n(char* a);

int get_mul(char* a,char* b);

int get_mod(char* a,char* b);

void reverse(char* a);

void get_a(char* a);

void get_g(char* a);

void get_p(char* a, int n);

void display(char* a);

void sent(int a, char* p, char* g, char* ans);

void rec(int b, char *p, char *g, char *ans);

void get_key(int b, char *rec, char*p, char*g, char *ans);



