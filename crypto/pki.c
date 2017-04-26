#include "pki.h"

// this function is GPL v2 from Irssi: https://github.com/irssi/irssi
/** check if a hostname in the certificate matches the hostname we used for the connection */
gboolean match_hostname(const char *cert_hostname, const char *hostname)
{
    const char *hostname_left;

    if (!strcasecmp(cert_hostname, hostname)) { /* exact match */
        return TRUE;
    } else if (cert_hostname[0] == '*' && cert_hostname[1] == '.' && cert_hostname[2] != 0) { /* wildcard match */
        /* The initial '*' matches exactly one hostname component */
        hostname_left = strchr(hostname, '.');
        if (hostname_left != NULL && ! strcasecmp(hostname_left + 1, cert_hostname + 2)) {
            return TRUE;
        }
    }
    return FALSE;
}

// this function is GPL v2 from Irssi: https://github.com/irssi/irssi
/* Checks if the given string has internal NUL characters. */
gboolean has_internal_nul(const char* str, int len) {
    /* Remove trailing nul characters. They would give false alarms */
    while (len > 0 && str[len-1] == 0)
        len--;
    return strlen(str) != len;
}

// this function is GPL v2 from Irssi: https://github.com/irssi/irssi
/* tls_text_name - extract certificate property value by name */
char *tls_text_name(X509_NAME *name, int nid) {
    int     pos;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *entry_str;
    int     utf8_length;
    unsigned char *utf8_value;
    char *result;

    if (name == 0 || (pos = X509_NAME_get_index_by_NID(name, nid, -1)) < 0) {
        return NULL;
    }

    entry = X509_NAME_get_entry(name, pos);
    g_return_val_if_fail(entry != NULL, NULL);
    entry_str = X509_NAME_ENTRY_get_data(entry);
    g_return_val_if_fail(entry_str != NULL, NULL);

    /* Convert everything into UTF-8. It's up to OpenSSL to do something
       reasonable when converting ASCII formats that contain non-ASCII
       content. */
    if ((utf8_length = ASN1_STRING_to_UTF8(&utf8_value, entry_str)) < 0) {
        g_warning("Error decoding ASN.1 type=%d", ASN1_STRING_type(entry_str));
        return NULL;
    }

    if (has_internal_nul((char *)utf8_value, utf8_length)) {
        g_warning("NUL character in hostname in certificate");
        OPENSSL_free(utf8_value);
        return NULL;
    }

    result = g_strdup((char *) utf8_value);
    OPENSSL_free(utf8_value);
    return result;
}
