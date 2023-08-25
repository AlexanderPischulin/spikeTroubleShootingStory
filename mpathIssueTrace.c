/*

Струкура dm-multipath устройства, с мажнорным и минорным номеромм устройств
dm-multipath усройство dm-7 имеет можнорный номер 253, минорный 7 (253:7)

R2D2_ssd_pool0_res3 (000000000000000000000000000000000) dm-7 
size=512G features='1 queue_if_no_path' hwhandler='1 alua' wp=rw
`-+- policy='service-time 0' prio=50 status=active
  |- 14:0:0:4  sdh  8:112  active ready running
  |- 16:0:0:4  sdr  65:16  active ready running
  |- 17:0:0:4  sdab 65:176 active ready running
  `- 18:0:0:4  sdal 66:80  active ready running
*/



/*

Формат структуры данных трейспоинта block_rq_issue

name: block_rq_issue
ID: 1051
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:dev_t dev;        offset:8;       size:4; signed:0;
        field:sector_t sector;  offset:16;      size:8; signed:0;
        field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
        field:unsigned int bytes;       offset:28;      size:4; signed:0;
        field:char rwbs[8];     offset:32;      size:8; signed:1;
        field:char comm[16];    offset:40;      size:16;        signed:1;
        field:__data_loc char[] cmd;    offset:56;      size:4; signed:1;

*/

/* Описание структуры аргумента для трейспоинтов block_rq_issue и block_rq_complete */

struct block_rq_args {


    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sectors;
    uint bytes;
    char rwbs[8];
    char comm[16];
    char __data_loc[4];
};


/*

Формат структуры данных трейспоинта block_rq_remap

name: block_rq_remap
ID: 1039
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:dev_t dev;        offset:8;       size:4; signed:0;
        field:sector_t sector;  offset:16;      size:8; signed:0;
        field:unsigned int nr_sector;   offset:24;      size:4; signed:0;
        field:dev_t old_dev;    offset:28;      size:4; signed:0;
        field:sector_t old_sector;      offset:32;      size:8; signed:0;
        field:unsigned int nr_bios;     offset:40;      size:4; signed:0;
        field:char rwbs[8];     offset:44;      size:8; signed:1;
*/

/* Описание структуры аргумента для трейспоинта block_rq_remap */

struct block_rq_remap_args {
	u64 __unused__;
	u32 dev;
	u64 sector;
	u32 nr_sectors;
	u32 old_dev;
	u64 old_sector;
	uint nr_bios;
	char rwbs[8];
};


/* 
   Структура описывающая операций ввода-вывода зерегистрировванных на блочных устройствах
   Времеменная метка
   Размер в байтах
*/

struct ioInfo {
    u64 ts;
    uint bytes;
};


/* 
   Хеш-таблица для регистрации событий на dm-multipath устройстве,
   ключом является номер сектора 
 */


BPF_HASH(dm7_253_7, u64, struct ioInfo, 10240); // dm-7 (253:7)

/*
  Хеш-таблицы для регистрации событий ввода-вывода на нижележащих
  блочных устройствах
*/

BPF_HASH(sdh_8_112, u64, struct ioInfo, 10240); // sdh (8:112)
BPF_HASH(sdr_65_16, u64, struct ioInfo, 10240); // sdr (65:16)
BPF_HASH(sdab_65_176, u64, struct ioInfo, 10240); // sdab (65:176)
BPF_HASH(sdal_66_80, u64, struct ioInfo, 10240); // sdal (66:80)


/* 
   Структура описывающая операции ввода-вывода подвергающиеся перенаправлению 
   Времеменная метка
   Размер в байтах
   Устройство на которое произошло переназначение
   Сектор
*/

struct ioInfoRemap {
    u64 ts;
    uint bytes;
    u32 dev;
    u64 sector;
};

/*
  Хеш-таблица для регистрации событий перенаправления, ключ - сектор
*/

BPF_HASH(dm7_253_7_remap, u64, struct ioInfoRemap, 10240);


/* 
  Фкнкция обработки события перенаправления 
*/

int traceRemap (struct block_rq_remap_args *args) {

/* 
  Игнорируем все события не являющиеся операцией записи
*/

 if (args->rwbs[0] != 'W') return 0;

/* 
  Подготавливаем и заполняем структуру описывающую перанаправленный запрос 
*/

struct ioInfoRemap io;
 __builtin_memset(&io, 0, sizeof(io));

io.ts = bpf_ktime_get_ns();
io.bytes=args->nr_sectors*512;
io.dev=args->dev;
io.sector=args->sector;


/* 
  Раскрываем мажорный и минорный номера устройства
*/  
int majorNum =  args->old_dev >> 20;
int minorNum =  ((int) ((args->old_dev) & ((1U << 20) - 1)));

/*
  Сохраняем сектор старого устройства для последующего использования 
  в качестве ключа для сохранения в хеш-таблице
*/
u64 sector=args->old_sector;

/*  
   Сохранение в заполененой структуры описывющей перенаправленную операцию
   в хеш-таблицы соответвующей нашему dm-multipath устройству
*/

switch (majorNum) {

      case 253:

           switch (minorNum) {

			//	Блочное устройств dm-7 (253:7)  
                case 7:
                     dm7_253_7_remap.update(&sector, &io);
                     break;
                default:
                     break;
                }
	default:
	   break;

       }

return 0;

}


/*
  Функция обработки события отправки запсроса
*/



int traceIssue (struct block_rq_args *args) {

/*
  Игнорируем все операции не явлющиеся записью
*/
 
 if (args->rwbs[0] != 'W') return 0; 


/* 
  Подготавливаем структуру и заполняем её значениями текущего времени 
  и размера блока
*/

  
 struct ioInfo io;
  __builtin_memset(&io, 0, sizeof(io));
 io.ts = bpf_ktime_get_ns();
 io.bytes = args->bytes;
 
 
 /* 
  Сохраняем в перемнной значение секотра для последующего использования 
  в качестве индекса
 */
 
 u64 sector=args->sector;


/* 
  Раскрываем мажорный и минорный номера устройства
*/    
 int majorNum =  args->dev >> 20;
 int minorNum =  ((int) ((args->dev) & ((1U << 20) - 1)));



 /*
   Основываясь на мажорном и минорном номерах устройств сохраняем в 
   хеш-таблице информацию о времени начала операции и размере блока 
   на интересующих нас блочных устройствах
 */
  
 switch (majorNum) {
	
      case 253:
           switch (minorNum) {	 	
				case 7:	
					dm7_253_7.update(&sector, &io);	// dm-7 253:7
					break;
				default:
					break;
			}
	 case 8:

	    switch (minorNum) {

                case 112:
                     sdh_8_112.update(&sector, &io); // sdh 8:112
                     break;
                default:
                     break;
		}
	 case 65:

            switch (minorNum) {

                case 16:
                     sdr_65_16.update(&sector, &io);  // sdr 65:16 
                     break;
                case 176:
                     sdab_65_176.update(&sector, &io);  // sdab 65:176 
                     break;
                default:
                     break;
		}
	 case 66:

            switch (minorNum) {

                case 80:
                     sdal_66_80.update(&sector, &io);  // sdal 66:80
                     break;
                default:
                     break;
		}

	default:
	     break;
    }
	 	
return 0;

}	 


/* 
   Функция обработки события заершения запроса. 
*/

int traceComplete (struct block_rq_args *args) {

/*
  Игнорируем все операции не явлющиеся записью
*/
 
 if (args->rwbs[0] != 'W') return 0; 

 
 
 u64 delta;
 struct ioInfo *io;
 struct ioInfo *io_inner;
 struct ioInfoRemap *io_remap;

 /* 
  Сохраняем в перемнной значение секотра для последующего использования 
  в качестве индекса поиска по таблицам устройств
 */
 
 u64 sector=args->sector;
 
 /*
   Раскрываем мажорный и минорный номера устройств
 */
 int majorNum =  args->dev >> 20;
 int minorNum =  ((int) ((args->dev) & ((1U << 20) - 1)));


  switch (majorNum) {

      case 253:

           switch (minorNum) {

/*
	Вычисляем время выполнения для операции на устростве верхнего уровня,
	в данном случае dm-mpath dm-7 (253:7)
 
 */
                case 7:
					io = dm7_253_7.lookup(&sector);
					if (io == 0) {
							return 0;   
						}
/*
	Вычисляем время выполнения операции,  если оно ниже порогового значения
	удаляем из таблиц записи соответсвуюшие сектору и завершаем обработку
 */
					delta = (bpf_ktime_get_ns() - io->ts)/1000/1000;
	
					if (delta < 1000) {
						dm7_253_7.delete(&sector);
						dm7_253_7_remap.delete(&sector);
						sdh_8_112.delete(&sector);
						sdr_65_16.delete(&sector);
						sdab_65_176.delete(&sector);
						sdal_66_80.delete(&sector);
						return 0;
					}
/*
	В противном случае печатаем интересующую нас информацию, вычисляем
	время от отпарвки события до операции remap, а затем производим поиск
	в таблицах нижележащих устройств операции соответствующей сектору и 
	вычисляем время выполнения на данном устройстве. После вычисления и
	распечатки интересующей информации записи в таблице удаляются
*/

					bpf_trace_printk ("Sector: %llx  size: %d  lat: %d", sector, io->bytes, delta);
					bpf_trace_printk ("Dev:  %d:%d  Op: %s",majorNum, minorNum, args->rwbs);
					bpf_trace_printk ("Issue timestamp on %d:%d :  %lld ",majorNum, minorNum, io->ts);
/* 
   Поиск в таблице dm7_253_7_remap структуры содержащей информацию о времени
   события перенаправления для текущего сектора
*/
					io_remap = dm7_253_7_remap.lookup(&sector);
					if (io_remap != 0) {
						delta = (bpf_ktime_get_ns() - io_remap->ts)/1000/1000;
						int majorNumRemap =  io_remap->dev >> 20;
						int minorNumRemap  =  ((int) ((io_remap->dev) & ((1U << 20) - 1)));
						bpf_trace_printk ("Remap sector: %llx, size: %d, lat %d", io_remap->sector, io_remap->bytes, delta);
						bpf_trace_printk ("Remap dev: %d:%d  ts:",  majorNumRemap, minorNumRemap, io_remap->ts);
/* 
  Удаление записи после обработки события 
*/		
						dm7_253_7_remap.delete(&sector);
					} else {
						bpf_trace_printk ("Remap event not found");
					}
/* 
   Поиск в таблицам нижележащих устройств записи содержащей информацию о
   времени события отравки запроса для текущего сектора
*/
	
					io_inner = sdh_8_112.lookup(&sector);
					if (io_inner != 0) {
						delta = (bpf_ktime_get_ns() - io_inner->ts)/1000/1000;
						bpf_trace_printk ("Maj: 8   Min: 112  lat: %d", delta);
/* 
  Удаление записей соответствущих текущему сектору в таблицах текущего устройства
  и устройства верхнего уровня
*/
						dm7_253_7.delete(&sector);
						sdh_8_112.delete(&sector);
						return 0;
					}
					
					io_inner = sdr_65_16.lookup(&sector);
					if (io_inner != 0) {
						delta = (bpf_ktime_get_ns() - io_inner->ts)/1000/1000;
						bpf_trace_printk ("Maj: 65   Min: 16  lat: %d", delta);
						dm7_253_7.delete(&sector);
						sdr_65_16.delete(&sector);
						return 0;
					}
                
					io_inner = sdab_65_176.lookup(&sector);
					if (io_inner != 0) {
						delta = (bpf_ktime_get_ns() - io_inner->ts)/1000/1000;
						bpf_trace_printk ("Maj: 65   Min: 176  lat: %d", delta);
						dm7_253_7.delete(&sector);
						sdab_65_176.delete(&sector);
						return 0;
					}
		   
					io_inner = sdal_66_80.lookup(&sector);
					if (io_inner != 0) {
						delta = (bpf_ktime_get_ns() - io_inner->ts)/1000/1000;
						bpf_trace_printk ("Maj: 66   Min: 80  lat: %d", delta);
						dm7_253_7.delete(&sector);
						sdal_66_80.delete(&sector);
						return 0;
					}

					bpf_trace_printk ("Inner event not found");
					break;

               default:
                     break;
           }

	default:
       break;
 }
return 0;

}
