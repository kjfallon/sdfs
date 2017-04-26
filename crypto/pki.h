//
// Created by seed on 4/26/17.
//

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifndef SDFS_PKI_H
#define SDFS_PKI_H

gboolean match_hostname(const char *cert_hostname, const char *hostname);
gboolean has_internal_nul(const char* str, int len);
char *tls_text_name(X509_NAME *name, int nid);

#endif //SDFS_PKI_H
