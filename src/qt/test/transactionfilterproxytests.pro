# Standalone proxy regression tests, without core/wallet dependencies.
QT = core testlib
CONFIG += console testcase c++11
CONFIG -= app_bundle
DEFINES += TRANSACTION_PROXY_STANDALONE_TEST
INCLUDEPATH += ../..
SOURCES += transactionfilterproxytests.cpp ../transactionfilterproxy.cpp
HEADERS += transactionfilterproxytests.h ../transactionfilterproxy.h
TARGET = transactionfilterproxytests

# Match configure's glibc endian feature checks for this Linux-only standalone build.
linux {
    DEFINES += HAVE_ENDIAN_H HAVE_BYTESWAP_H
    DEFINES += HAVE_DECL_HTOBE16=1 HAVE_DECL_HTOLE16=1 HAVE_DECL_BE16TOH=1 HAVE_DECL_LE16TOH=1
    DEFINES += HAVE_DECL_HTOBE32=1 HAVE_DECL_HTOLE32=1 HAVE_DECL_BE32TOH=1 HAVE_DECL_LE32TOH=1
    DEFINES += HAVE_DECL_HTOBE64=1 HAVE_DECL_HTOLE64=1 HAVE_DECL_BE64TOH=1 HAVE_DECL_LE64TOH=1
    DEFINES += HAVE_DECL_BSWAP_16=1 HAVE_DECL_BSWAP_32=1 HAVE_DECL_BSWAP_64=1
}
