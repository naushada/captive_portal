#ifndef __DB_C__
#define __DB_C__

#include <common.h>
//#include <my_global.h>
#include <mysql.h>

#include <db.h>

db_ctx_t mysql_ctx_g;

int db_init(char *db_conn_info[]) {
  int ret = -1;
  db_ctx_t *pDbCtx = &mysql_ctx_g;

  /*mysql_conn will be allocated by mysql_init and will be freed by invoking mysql_close*/
  pDbCtx->server_handle.mysql_conn = mysql_init(NULL);

  if(NULL == pDbCtx->server_handle.mysql_conn) {
    fprintf(stderr, "\nInsufficient memory to allocate a new object");
    return(ret); 
  }
  
  /*Extracting mysql db connection configuration*/
  memcpy(pDbCtx->server_config.server_ip, db_conn_info[0], strlen(db_conn_info[0]));
  memcpy(pDbCtx->server_config.db_name,   db_conn_info[1], strlen(db_conn_info[1]));
  memcpy(pDbCtx->server_config.user_name, db_conn_info[2], strlen(db_conn_info[2]));
  memcpy(pDbCtx->server_config.password,  db_conn_info[3], strlen(db_conn_info[3]));
  pDbCtx->server_config.server_port = (unsigned short int)atoi(db_conn_info[4]); 
  
  ret = 0;
  return(ret);

}/*db_init*/



int db_connect(void) {
  int ret = -1;
  db_ctx_t *pDbCtx = &mysql_ctx_g;
  MYSQL *pConn = NULL;
#if 0
  /*int mysql_options(MYSQL *mysql, enum mysql_option option, const void *arg)*/
  ret = mysql_options(pDbCtx->server_handle.mysql_conn, MYSQL_OPT_PROTOCOL, (const void *)MYSQL_PROTOCOL_TCP);
  
  if(ret) {
    /*free the allocated memory*/
    mysql_close(pDbCtx->server_handle.mysql_conn);
    pDbCtx->server_handle.mysql_conn = NULL;
    fprintf(stderr, "\n Unknown option has been specified for PROTOCOL");
    return(ret);
  }
#endif
  ret = -1;
  /*MYSQL *mysql_real_connect(MYSQL *mysql, const char *host, const char *user, 
                              const char *passwd, const char *db, unsigned int port, 
                              const char *unix_socket, unsigned long client_flag)*/
  pConn = mysql_real_connect(pDbCtx->server_handle.mysql_conn,
                             pDbCtx->server_config.server_ip,
                             pDbCtx->server_config.user_name,
                             pDbCtx->server_config.password,
                             pDbCtx->server_config.db_name,
                             pDbCtx->server_config.server_port,
                             NULL, 0);
  
  if((NULL == pConn) || (pConn != pDbCtx->server_handle.mysql_conn)) {
    /*free the allocated memory*/
    mysql_close(pDbCtx->server_handle.mysql_conn);
    pDbCtx->server_handle.mysql_conn = NULL;
    fprintf(stderr, "\nConnection to database failed");
    return(ret);
  }
  /*upon success pConn will be same as pDbCtx->server_handle.mysql_conn*/
  ret = 0;
  return(ret);
}/*db_connect*/

int db_exec_query(char *sql_query) {
  int ret = -1;
  db_ctx_t *pDbCtx = &mysql_ctx_g;
  
  /*int mysql_query(MYSQL *mysql, const char *stmt_str)*/ 
  ret = mysql_query(pDbCtx->server_handle.mysql_conn, (const char *)sql_query);

  if(ret) {
    fprintf(stderr, "\nExecution of query %s failed", sql_query);
    return(ret);
  }
  
  pDbCtx->server_handle.mysql_query_result = mysql_store_result(pDbCtx->server_handle.mysql_conn);
  return(0);
 
}/*db_exec_query*/

int db_process_query_result(int *row_count, int *column_count, char result[2][16][32]) {
  int ret = -1;
  int row = -1;
  int col = -1;
  
  unsigned long *len = NULL;
  MYSQL_ROW  record;

  db_ctx_t *pDbCtx = &mysql_ctx_g;

  /*my_ulonglong mysql_num_rows(MYSQL_RES *result)*/
  row = (int) mysql_num_rows(pDbCtx->server_handle.mysql_query_result);
  *row_count = row;

  /*unsigned int mysql_field_count(MYSQL *mysql)*/ 
  col = (unsigned int) mysql_field_count(pDbCtx->server_handle.mysql_conn);
  *column_count = col;

  for(row = 0; row < *row_count; row++) {
    /*Retrieve the row of a given table*/
    record = mysql_fetch_row(pDbCtx->server_handle.mysql_query_result);
     
    /*unsigned long *mysql_fetch_lengths(MYSQL_RES *result)*/
    len = mysql_fetch_lengths(pDbCtx->server_handle.mysql_query_result);

    for(col = 0; col < *column_count; col++) {
      memcpy((void *)result[row][col], record[col], len[col]);
    }
  }
  ret = 0;
  return(ret);
}/*db_process_query_result*/



#endif

