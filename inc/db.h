#ifndef __DB_H__
#define __DB_H__

typedef struct {
  char server_ip[32];
  char db_name[32];
  char user_name[32];
  char password[32];  
  unsigned short int server_port;
}db_mysql_server_cfg_t;

typedef struct {
  MYSQL     *mysql_conn;
  MYSQL_RES *mysql_query_result;
 
}db_mysql_handle_t;

typedef struct {
  db_mysql_server_cfg_t server_config;
  db_mysql_handle_t     server_handle;
 
}db_ctx_t;

int db_init(char *db_conn_info[]);
int db_connect(void);
int db_exec_query(char *sql_query);
int db_process_query_result(int *row_count, int *column_count, char result[2][16][32]);

#endif
