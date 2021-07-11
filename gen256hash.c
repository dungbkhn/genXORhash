#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>


//gcc gen256hash.c -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64 -o gen256hash.out

#define MYSIZE_L1 1048576 //1024*1024 for filesize < 16 M = 16777216
#define MYSIZE_L2 16777216 //16*1024*1024 for filesize < 256 M = 268435456
#define MYSIZE_L3 268435456 //256*1024*1024 others

#define MAX_LINE_LENGTH 256
#define MAX_XOR_LENGTH 16384


//const char outputfilename_temp[MAX_LINE_LENGTH]="/home/dungnt/Cplusplus/sha256/outfile_sha256_temp.txt";
const char outputfilename_temp[MAX_LINE_LENGTH]="/home/backup/sha256/outfile_sha256_temp.txt";

int getSshUserNum() {
	char cmd[MAX_LINE_LENGTH]="netstat -atn 2>&1 | grep ':22 ' 2>&1 | grep 'ESTABLISHED' 2>&1";
	FILE * stream;
	char buffer[MAX_LINE_LENGTH];
	size_t n;
	int kq=0;
	
	stream = popen(cmd, "r");
	if (stream) {
		while (!feof(stream)){
			if (fgets(buffer, 256, stream) != NULL){
				//printf("ExecutionRes:%s %d",buffer,(unsigned)strlen(buffer));
				n = strlen(buffer);
				buffer[n]='\0';
				//printf("%ldExecutionRes:%s\n",n,buffer);
				if(strstr(buffer, "HED") != NULL)
					kq++;
			}
		}
		pclose(stream);
	}
	else
		return -2;
		
	/**********************
	//kq "number ssh user active"
	* =0 : no ssh user active
	* >0 : number ssh user active
	* -2 : run error
	***********************/
	
	return kq;
}


int checksleep(const char* web_logfile_readin){
	int bl=0;
	char line[MAX_LINE_LENGTH] = {0};
	char* eptr;
	FILE* file = fopen(web_logfile_readin, "r");
	
    if (!file) {
        perror("fopen");
        return -2;
    }
    else{
		while(fgets(line,MAX_LINE_LENGTH,file)){
			//printf("%s",line);
		}
		
		long long int a = strtoll(line,&eptr,10);
		a=a/1000;
		//printf("%lld\n",a);
			
		struct timeval start;
		gettimeofday(&start, NULL);
		long long int b = (start.tv_sec) + start.tv_usec/1000000;
		//printf("took %lld s\n", b); 
		
		if((b-a) < 315){
			//printf("web user still active\n");
			bl=-1;
		}
		
		fclose(file);
	}

	if(bl==0){
		bl=getSshUserNum();
	}
	
	/***************************
	//-2: run error
	//-1: web user still active
	//>0: number ssh user active
	//=0: server not busy
	****************************/
	
	return bl;
}


int gensha256(int num, int MYSIZE, char* filename_need_genhash, const char *logfilename){
    int i,j,k,csl;
    
	FILE* out_file = fopen( outputfilename_temp , "w" );
    FILE* in_file = fopen(filename_need_genhash, "rb");
    char* file_contents = (char*)malloc(MAX_XOR_LENGTH);
    char* init_xor_content = (char*)malloc(MAX_XOR_LENGTH);
    
    memset(init_xor_content,0,MAX_XOR_LENGTH);
    memset(file_contents,0,MAX_XOR_LENGTH);
    
    if (!in_file){
        perror("fopen filename_need_genhash");
        return -2;
    }
 
	if (!out_file) {
		perror("fopen filename_output");
        return -2;
	}
	
	//fprintf(out_file,"filename_need_hash:%s MYSIZE=%d num=%d\n",filename_need_genhash,MYSIZE,num);
    
    //can jump two times
    //fseek(in_file, offset, SEEK_SET);
    //fseek(in_file, offset, SEEK_CUR);
    
    //set at the beginning
    fseek(in_file, 0L, SEEK_SET);

	i=0;
	
    while(i<num){
		k=0;
		memset(init_xor_content,0,MAX_XOR_LENGTH);
		memset(file_contents,0,MAX_XOR_LENGTH);
		
		while(k < MYSIZE){
			fread(file_contents, MAX_XOR_LENGTH, 1, in_file);
			for (j = 0; j < MAX_XOR_LENGTH; j++){				
				init_xor_content[j]=init_xor_content[j]^file_contents[j];
			}
			k=k + MAX_XOR_LENGTH;
		}
		
		for (j = 0; j < MAX_XOR_LENGTH; j++){	
			//fwrite(str , 1 , sizeof(str) , fp );
			fprintf(out_file,"%02x", init_xor_content[j]);
		}
		
		fprintf(out_file,"\n");
		
		csl = checksleep(logfilename);
		//fprintf(out_file,"csl:%d\n",csl);
		if(csl!=0){
			j=0;
			
			while((j < 5)&&(csl!=0)){
				sleep(1);
				csl = checksleep(logfilename);
				j++;
			}
			
			if((j == 5)&&(csl!=0)){
				fclose(in_file);
				fclose(out_file);
				free(file_contents);
				
				return -2;//thoat while (i<num), nghi khoang thoi gian dai
			}
		}

		i++;
	}
    
    fclose(in_file);
	fclose(out_file);
	
	free(file_contents);
	
	return 1;
}


int main(int argc, char *argv[]) {
	
	int i,j;
	//const char logfilename[MAX_LINE_LENGTH]="/home/dungnt/Cplusplus/sha256/logtimefile.txt";
	//const char outputfilename[MAX_LINE_LENGTH]="/home/dungnt/Cplusplus/sha256/outfile_sha256.txt";
	//const char filename_readin[MAX_LINE_LENGTH]="/home/dungnt/Cplusplus/sha256/listfile.txt";
	//const char logfilename_genhashC[MAX_LINE_LENGTH]="/home/dungnt/Cplusplus/sha256/genhashC_logfile.txt";
	
	const char logfilename[MAX_LINE_LENGTH]="/home/dungnt/MyDisk_With_FTP/logtime/logtimefile.txt";
	const char outputfilename[MAX_LINE_LENGTH]="/home/backup/sha256/outfile_sha256.txt";
	const char filename_readin[MAX_LINE_LENGTH]="/home/backup/sha256/listfile.txt";
	const char logfilename_genhashC[MAX_LINE_LENGTH]="/home/backup/sha256/genhashC_logfile.txt";
	
	char *filename_need_hash;
	char line[MAX_LINE_LENGTH] = {0};
	
	int count;
	int level,num;
    
    
    
    while(true){
		
		//FILE* out_logfile = fopen( logfilename_genhashC , "a" );
		
		if(access(filename_readin,F_OK) == 0) {//file exists
			FILE* in_file = fopen(filename_readin, "r");
			if (!in_file) {
				perror("fopen filename_readin");
				exit(EXIT_FAILURE);
			}
			
			count=0;
			while(fgets(line,MAX_LINE_LENGTH,in_file)){
				//printf("%s",line);
				if(count==0){			
					level = (int)strtol(line, NULL, 10);
					if(level==3)
						level=MYSIZE_L3;
					else if(level==2)
						level=MYSIZE_L2;
					else
						level=MYSIZE_L1;
						
					memset(line,0,MAX_LINE_LENGTH);
				}
				else if(count==1){
					num = (int)strtol(line, NULL, 10);
					memset(line,0,MAX_LINE_LENGTH);
				}
				else
					filename_need_hash = line;
				
				count++;
			}
			
			fclose(in_file);
			
			i = strlen(filename_need_hash);
			filename_need_hash[i-1]='\0';
			
			remove(filename_readin);
			remove(outputfilename);
			remove(outputfilename_temp);
			
			if((num!=0)&&(access(filename_need_hash,F_OK) == 0)){
				
				i=gensha256(num,level,filename_need_hash,logfilename);
				
				if(i==-2) {
					remove(outputfilename_temp);
					
					FILE* outputfile = fopen( outputfilename , "w" );
					//memset(buf,0,SHA256_BLOCK_SIZE);
					fprintf(outputfile,"######");
					fclose(outputfile);
					//for log
					//fprintf(out_logfile,"remove both outputfilename_temp inputfilename\n");
					//fprintf(out_logfile,"long sleep\n");
					//fclose(out_logfile);
					//end log
					sleep(45);//nghi dai 
				} else {
					rename(outputfilename_temp,outputfilename);
					//for log
					//fprintf(out_logfile,"output ok\n");
					//fclose(out_logfile);
					//end log
				}
			}
			else{
				//fclose(out_logfile);
				sleep(45);//nghi dai 
			}
		}
		else{
			//perror("File not found");
			//fclose(out_logfile);
			sleep(10);//nghi ngan
		}

	}
	
	
	
	//for test
	/*
	while(true){
		//i=getSshUserNum();
		//i=checksleep(logfilename);
		char inputfilename[MAX_LINE_LENGTH]="/home/backup/sha256/input.txt";
		i=gensha256(5,MYSIZE_L1,inputfilename,outputfilename,logfilename);
		printf("%d\n",i);
		sleep(10);
	}
	*/
	
	exit(EXIT_SUCCESS);
}
