#!/usr/bin/python3

from bcc import BPF


bpf_text = """

/*

name: block_rq_requeue
ID: 1055
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:dev_t dev;        offset:8;       size:4; signed:0;
        field:sector_t sector;  offset:16;      size:8; signed:0;
        field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
        field:char rwbs[8];     offset:28;      size:8; signed:1;
        field:__data_loc char[] cmd;    offset:36;      size:4; signed:1;

print fmt: "%d,%d %s (%s) %llu + %u [%d]", ((unsigned int) ((REC->dev) >> 20)), ((unsigned int) ((REC->dev) & ((1U << 20) - 1))), REC->rwbs, __get_str(cmd), (unsigned long long)REC->sector, REC->nr_sector, 0
*/

/*
 Структура для чтения аргумента трейспоинта block_requeue
 Мажорный и монорный номера устройства 
 Сектор
 Кол-во секторов - размер блока
 Тип операции
*/

struct block_requeue_args {

    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sectors;
    char rwbs[8];
    char __data_loc[4];
};

/* 
  Функция обработки события повторной постановки в очередь
*/


int traceRequeue (struct block_requeue_args  *args) {

/* 
  Игнорируем все операции не являющиеся записью 
*/

 if (args->rwbs[0] != 'W') return 0;

/* 
  Раскрываем мажорный и минорные номера устройства и печатаем информацию о событии 
*/

 int majorNum =  args->dev >> 20;
 int minorNum =  ((int) ((args->dev) & ((1U << 20) - 1)));

 bpf_trace_printk ("Requeue Dev: %d:%d Sector: %llx", majorNum, minorNum, args->sector);
 
 return 0;
}
"""

b = BPF(text=bpf_text)

b.attach_tracepoint(tp="block:block_rq_requeue", fn_name="traceRequeue")
b.trace_print()
