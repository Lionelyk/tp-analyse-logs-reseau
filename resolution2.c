#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 256

typedef struct {
    char date[20];
    char heure[20];
    char ip[20];
    int port;
    char protocole[10];
    char statut[10];
} Log;

typedef struct {
    char ip[20];
    int port;
    int echec_count;
} Suspect;

/* ===== Lecture des logs ===== */
Log* lireLogs(const char* filename, int* count) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Erreur ouverture fichier.\n");
        exit(1);
    }

    Log* logs = NULL;
    char line[MAX_LINE];
    *count = 0;

    while (fgets(line, sizeof(line), file)) {
        logs = realloc(logs, (*count + 1) * sizeof(Log));

        char* token = strtok(line, ";");
        strcpy(logs[*count].date, token);

        token = strtok(NULL, ";");
        strcpy(logs[*count].heure, token);

        token = strtok(NULL, ";");
        strcpy(logs[*count].ip, token);

        token = strtok(NULL, ";");
        logs[*count].port = atoi(token);

        token = strtok(NULL, ";");
        strcpy(logs[*count].protocole, token);

        token = strtok(NULL, ";\n");
        strcpy(logs[*count].statut, token);

        (*count)++;
    }

    fclose(file);
    return logs;
}

/* ===== Analyse ===== */
void analyserLogs(Log* logs, int count) {

    int succes = 0, echec = 0;

    int ports[1000] = {0};  // index = numéro port
    char ips[200][20];
    int ip_count[200] = {0};
    int unique_ips = 0;

    Suspect suspects[200];
    int suspect_count = 0;

    for (int i = 0; i < count; i++) {

        /* succès / échec */
        if (strcmp(logs[i].statut, "SUCCES") == 0)
            succes++;
        else
            echec++;

        /* comptage ports */
        ports[logs[i].port]++;

        /* comptage IP */
        int found = 0;
        for (int j = 0; j < unique_ips; j++) {
            if (strcmp(ips[j], logs[i].ip) == 0) {
                ip_count[j]++;
                found = 1;
                break;
            }
        }

        if (!found) {
            strcpy(ips[unique_ips], logs[i].ip);
            ip_count[unique_ips]++;
            unique_ips++;
        }

        /* détection échecs suspects */
        if (strcmp(logs[i].statut, "ECHEC") == 0) {
            int found_s = 0;
            for (int k = 0; k < suspect_count; k++) {
                if (strcmp(suspects[k].ip, logs[i].ip) == 0 &&
                    suspects[k].port == logs[i].port) {

                    suspects[k].echec_count++;
                    found_s = 1;
                    break;
                }
            }

            if (!found_s) {
                strcpy(suspects[suspect_count].ip, logs[i].ip);
                suspects[suspect_count].port = logs[i].port;
                suspects[suspect_count].echec_count = 1;
                suspect_count++;
            }
        }
    }

    /* port le plus utilisé */
    int max_port = 0;
    int port_plus_utilise = 0;
    for (int i = 0; i < 1000; i++) {
        if (ports[i] > max_port) {
            max_port = ports[i];
            port_plus_utilise = i;
        }
    }

    /* IP la plus active */
    int max_ip = 0;
    char ip_plus_active[20];
    for (int i = 0; i < unique_ips; i++) {
        if (ip_count[i] > max_ip) {
            max_ip = ip_count[i];
            strcpy(ip_plus_active, ips[i]);
        }
    }

    /* Affichage console */
    printf("\n=== RESULTATS ===\n");
    printf("Total connexions : %d\n", count);
    printf("Total succes : %d\n", succes);
    printf("Total echec : %d\n", echec);
    printf("Port le plus utilise : %d\n", port_plus_utilise);
    printf("IP la plus active : %s\n", ip_plus_active);

    printf("\n=== IP SUSPECTES ===\n");
    for (int i = 0; i < suspect_count; i++) {
        if (suspects[i].echec_count > 5) {
            printf("%s sur port %d (%d echecs)\n",
                   suspects[i].ip,
                   suspects[i].port,
                   suspects[i].echec_count);
        }
    }

    /* Génération rapport */
    FILE* rapport = fopen("rapport_analyse.txt", "w");
    fprintf(rapport, "=== RAPPORT D'ANALYSE RESEAU ===\n\n");
    fprintf(rapport, "Total connexions : %d\n", count);
    fprintf(rapport, "Total succes : %d\n", succes);
    fprintf(rapport, "Total echec : %d\n", echec);
    fprintf(rapport, "Port le plus utilise : %d\n", port_plus_utilise);
    fprintf(rapport, "IP la plus active : %s\n\n", ip_plus_active);

    fprintf(rapport, "=== IP SUSPECTES ===\n");
    for (int i = 0; i < suspect_count; i++) {
        if (suspects[i].echec_count > 5) {
            fprintf(rapport, "%s sur port %d (%d echecs)\n",
                    suspects[i].ip,
                    suspects[i].port,
                    suspects[i].echec_count);
        }
    }

    fclose(rapport);
}

/* ===== MAIN ===== */
int main() {
    int count = 0;
    Log* logs = lireLogs("network_log.txt", &count);

    analyserLogs(logs, count);

    free(logs);
    return 0;
}
