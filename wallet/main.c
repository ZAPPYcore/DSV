/**
 * DSV Wallet CLI
 * 
 * Secure wallet with TSA (2-of-3) passphrase protection.
 */

#include "dsv_wallet.h"
#include "dsv_crypto.h"
#include "dsv_serialize.h"
#include "dsv_u320.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

/* Read passphrase without echo */
static char *read_passphrase(const char *prompt) {
    static char pass[256];
    struct termios old_term, new_term;
    
    printf("%s", prompt);
    fflush(stdout);
    
    /* Disable echo */
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    if (fgets(pass, sizeof(pass), stdin) == NULL) {
        pass[0] = '\0';
    }
    
    /* Restore echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");
    
    /* Remove newline */
    size_t len = strlen(pass);
    if (len > 0 && pass[len - 1] == '\n') {
        pass[len - 1] = '\0';
    }
    
    return pass;
}

static void print_usage(const char *prog) {
    printf("DSV Wallet v1.0.0\n\n");
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  create      Create a new wallet with 3 passphrases (2-of-3 to unlock)\n");
    printf("  open        Open existing wallet\n");
    printf("  newaddr     Generate a new address\n");
    printf("  listaddr    List all addresses\n");
    printf("  balance     Show address balance (requires RPC)\n");
    printf("  send        Send DSV to an address\n");
    printf("  sign        Sign a raw transaction\n");
    printf("  export      Export mnemonic backup\n");
    printf("  import      Import wallet from mnemonic\n\n");
    printf("Options:\n");
    printf("  -w, --wallet=PATH   Wallet file (default: ~/.dsv/wallet.dat)\n");
    printf("  -r, --rpc=URL       RPC endpoint (default: http://127.0.0.1:8332)\n");
    printf("  -a, --auth=TOKEN    RPC auth token\n");
    printf("  -h, --help          Show this help\n");
}

static void cmd_create(const char *wallet_path) {
    printf("Creating new DSV wallet with TSA protection (2-of-3 passphrases)\n\n");
    printf("You will create 3 passphrases. Any 2 of 3 are needed to unlock.\n");
    printf("Store them securely in different locations!\n\n");
    
    char *pass1 = strdup(read_passphrase("Passphrase 1: "));
    char *pass1_confirm = strdup(read_passphrase("Confirm passphrase 1: "));
    
    if (strcmp(pass1, pass1_confirm) != 0) {
        printf("Error: Passphrases don't match\n");
        dsv_secure_zero(pass1, strlen(pass1));
        dsv_secure_zero(pass1_confirm, strlen(pass1_confirm));
        free(pass1);
        free(pass1_confirm);
        return;
    }
    free(pass1_confirm);
    
    char *pass2 = strdup(read_passphrase("Passphrase 2: "));
    char *pass2_confirm = strdup(read_passphrase("Confirm passphrase 2: "));
    
    if (strcmp(pass2, pass2_confirm) != 0) {
        printf("Error: Passphrases don't match\n");
        dsv_secure_zero(pass1, strlen(pass1));
        dsv_secure_zero(pass2, strlen(pass2));
        dsv_secure_zero(pass2_confirm, strlen(pass2_confirm));
        free(pass1);
        free(pass2);
        free(pass2_confirm);
        return;
    }
    free(pass2_confirm);
    
    char *pass3 = strdup(read_passphrase("Passphrase 3: "));
    char *pass3_confirm = strdup(read_passphrase("Confirm passphrase 3: "));
    
    if (strcmp(pass3, pass3_confirm) != 0) {
        printf("Error: Passphrases don't match\n");
        dsv_secure_zero(pass1, strlen(pass1));
        dsv_secure_zero(pass2, strlen(pass2));
        dsv_secure_zero(pass3, strlen(pass3));
        dsv_secure_zero(pass3_confirm, strlen(pass3_confirm));
        free(pass1);
        free(pass2);
        free(pass3);
        free(pass3_confirm);
        return;
    }
    free(pass3_confirm);
    
    dsv_wallet_t *wallet = dsv_wallet_create(wallet_path, pass1, pass2, pass3);
    
    dsv_secure_zero(pass1, strlen(pass1));
    dsv_secure_zero(pass2, strlen(pass2));
    dsv_secure_zero(pass3, strlen(pass3));
    free(pass1);
    free(pass2);
    free(pass3);
    
    if (!wallet) {
        printf("Error: Failed to create wallet\n");
        return;
    }
    
    /* Generate first address */
    dsv_address_t addr;
    if (dsv_wallet_new_address(wallet, &addr) == DSV_OK) {
        char addr_str[DSV_ADDRESS_STR_SIZE];
        dsv_address_encode(addr_str, sizeof(addr_str), &addr);
        printf("\nWallet created successfully!\n");
        printf("First address: %s\n", addr_str);
    }
    
    /* Export mnemonic */
    char mnemonic[512];
    if (dsv_wallet_export_mnemonic(wallet, mnemonic, sizeof(mnemonic)) == DSV_OK) {
        printf("\nBackup mnemonic (WRITE THIS DOWN!):\n%s\n", mnemonic);
        dsv_secure_zero(mnemonic, sizeof(mnemonic));
    }
    
    dsv_wallet_close(wallet);
    printf("\nWallet saved to: %s\n", wallet_path);
}

static dsv_wallet_t *open_wallet(const char *wallet_path) {
    printf("Opening wallet (enter any 2 of 3 passphrases)\n\n");
    
    char *pass_a = strdup(read_passphrase("First passphrase: "));
    char *pass_b = strdup(read_passphrase("Second passphrase: "));
    
    dsv_wallet_t *wallet = dsv_wallet_open(wallet_path, pass_a, pass_b);
    
    dsv_secure_zero(pass_a, strlen(pass_a));
    dsv_secure_zero(pass_b, strlen(pass_b));
    free(pass_a);
    free(pass_b);
    
    if (!wallet) {
        printf("Error: Failed to open wallet (wrong passphrases?)\n");
        return NULL;
    }
    
    printf("Wallet unlocked successfully!\n\n");
    return wallet;
}

static void cmd_newaddr(const char *wallet_path) {
    dsv_wallet_t *wallet = open_wallet(wallet_path);
    if (!wallet) return;
    
    dsv_address_t addr;
    if (dsv_wallet_new_address(wallet, &addr) == DSV_OK) {
        char addr_str[DSV_ADDRESS_STR_SIZE];
        dsv_address_encode(addr_str, sizeof(addr_str), &addr);
        printf("New address: %s\n", addr_str);
    } else {
        printf("Error: Failed to generate address\n");
    }
    
    dsv_wallet_close(wallet);
}

static void cmd_listaddr(const char *wallet_path) {
    dsv_wallet_t *wallet = open_wallet(wallet_path);
    if (!wallet) return;
    
    size_t count;
    dsv_address_t *addrs = dsv_wallet_get_addresses(wallet, &count);
    
    if (count == 0) {
        printf("No addresses in wallet\n");
    } else {
        printf("Addresses (%zu):\n", count);
        for (size_t i = 0; i < count; i++) {
            char addr_str[DSV_ADDRESS_STR_SIZE];
            dsv_address_encode(addr_str, sizeof(addr_str), &addrs[i]);
            printf("  %zu: %s\n", i + 1, addr_str);
        }
        free(addrs);
    }
    
    dsv_wallet_close(wallet);
}

static void cmd_export(const char *wallet_path) {
    dsv_wallet_t *wallet = open_wallet(wallet_path);
    if (!wallet) return;
    
    char mnemonic[512];
    if (dsv_wallet_export_mnemonic(wallet, mnemonic, sizeof(mnemonic)) == DSV_OK) {
        printf("Backup mnemonic:\n%s\n", mnemonic);
        dsv_secure_zero(mnemonic, sizeof(mnemonic));
    } else {
        printf("Error: Failed to export mnemonic\n");
    }
    
    dsv_wallet_close(wallet);
}

int main(int argc, char **argv) {
    const char *wallet_path = NULL;
    const char *rpc_url = "http://127.0.0.1:8332";
    const char *auth_token = NULL;
    
    static struct option long_options[] = {
        {"wallet", required_argument, 0, 'w'},
        {"rpc", required_argument, 0, 'r'},
        {"auth", required_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "w:r:a:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'w':
                wallet_path = optarg;
                break;
            case 'r':
                rpc_url = optarg;
                break;
            case 'a':
                auth_token = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Default wallet path */
    char default_path[512];
    if (!wallet_path) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(default_path, sizeof(default_path), "%s/.dsv/wallet.dat", home);
            wallet_path = default_path;
        } else {
            wallet_path = "wallet.dat";
        }
    }
    
    /* Initialize crypto */
    if (dsv_crypto_init() != DSV_OK) {
        fprintf(stderr, "Error: Failed to initialize cryptographic subsystem\n");
        return 1;
    }
    
    /* Get command */
    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[optind];
    (void)rpc_url;
    (void)auth_token;
    
    if (strcmp(command, "create") == 0) {
        cmd_create(wallet_path);
    } else if (strcmp(command, "open") == 0) {
        dsv_wallet_t *wallet = open_wallet(wallet_path);
        if (wallet) {
            printf("Wallet is valid and unlocked.\n");
            dsv_wallet_close(wallet);
        }
    } else if (strcmp(command, "newaddr") == 0) {
        cmd_newaddr(wallet_path);
    } else if (strcmp(command, "listaddr") == 0 || strcmp(command, "list") == 0) {
        cmd_listaddr(wallet_path);
    } else if (strcmp(command, "export") == 0) {
        cmd_export(wallet_path);
    } else if (strcmp(command, "balance") == 0 ||
               strcmp(command, "send") == 0 ||
               strcmp(command, "sign") == 0) {
        printf("Command '%s' requires RPC connection to node.\n", command);
        printf("Use: dsv-cli for these operations.\n");
    } else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}

