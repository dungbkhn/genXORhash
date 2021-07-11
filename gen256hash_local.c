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


//gcc gen256hash_local.c -D_LARGEFILE_SOURCE=1 -D_FILE_OFFSET_BITS=64 -o gen256hash_local.out
//./gen256hash_local.out /home/dungnt/ShellScript/sshsyncapp/.temp/listfile.txt /home/dungnt/ShellScript/sshsyncapp/.temp/outfile_sha256_local.txt /home/dungnt/ShellScript/sshsyncapp/.temp/outfile_sha256_local_temp.txt
//fileread:/home/dungnt/ShellScript/sshsyncapp/.temp/listfile.txt

#define MYSIZE_L1 1048576 //1024*1024 for filesize < 16 M = 16777216
#define MYSIZE_L2 16777216 //16*1024*1024 for filesize < 256 M = 268435456
#define MYSIZE_L3 268435456 //256*1024*1024 others

#define MAX_LINE_LENGTH 256
#define MAX_XOR_LENGTH 16384

//SHA256_CTX ctx;
//BYTE buf[SHA256_BLOCK_SIZE];


int checksleep(){
	int bl=0;
	
	
	/***************************
	//=0: server not busy
	****************************/
	
	return bl;
}


int gensha256(int num, int MYSIZE, char* filename_need_genhash, const char *outputfilename_temp){
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
		
		csl = checksleep();
		//fprintf(out_file,"csl:%d\n",csl);
		if(csl!=0){
			j=0;
			
			while((j < 5)&&(csl!=0)){
				sleep(1);
				csl = checksleep();
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
	printf("hash success\n");
	return 1;
}


int main(int argc, char *argv[]) {
	
	int i,j;
	
	char *outputfilename;//[MAX_LINE_LENGTH]="outfile_sha256_local.txt";
	char *filename_readin;//[MAX_LINE_LENGTH]="listfile.txt";
	//const char logfilename_genhashC[MAX_LINE_LENGTH]="genhashC_logfile.txt";
	char *outputfilename_temp;//[MAX_LINE_LENGTH]="outfile_sha256_local_temp.txt";
	
	//char *workingdir;
	char *filename_need_hash;
	char line[MAX_LINE_LENGTH] = {0};
	
	int count;
	int level,num;

	if( argc == 4 ) {
      filename_readin = argv[1];
      outputfilename = argv[2];
      outputfilename_temp = argv[3];
      printf("fileread:%s\n",filename_readin);
      printf("outputfilename:%s\n",outputfilename);
      printf("outputfilename_temp:%s\n",outputfilename_temp);
    }
    else {
      printf("Argument not expected.\n");
      exit(EXIT_FAILURE);
    }
    
    
	//FILE* out_logfile = fopen( logfilename_genhashC , "a" );
	
	if(access(filename_readin,F_OK) == 0) {//file exists
		FILE* in_file = fopen(filename_readin, "r");
		if (!in_file) {
			perror("fopen filename_readin");
			exit(EXIT_FAILURE);
		}
		
		count=0;
		while(fgets(line,MAX_LINE_LENGTH,in_file)){
			printf("%s",line);
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
		printf("%s\n",filename_need_hash);
		remove(filename_readin);
		remove(outputfilename);
		remove(outputfilename_temp);
		
		printf("remove ok\n");
		if((num!=0)&&(access(filename_need_hash,F_OK) == 0)){
			printf("begin hash\n");
			i=gensha256(num,level,filename_need_hash,outputfilename_temp);
			
			if(i==-2) {
				remove(outputfilename_temp);
				
				FILE* outputfile = fopen( outputfilename , "w" );
				fprintf(outputfile,"######");
				fclose(outputfile);
				//for log
				//fprintf(out_logfile,"remove both outputfilename_temp inputfilename\n");
				//fprintf(out_logfile,"long sleep\n");
				//fclose(out_logfile);
				//end log
				
			} else {
				rename(outputfilename_temp,outputfilename);
				//for log
				//fprintf(out_logfile,"output ok\n");
				//fclose(out_logfile);
				//end log
			}
		}
		else{
			FILE* outputfile = fopen( outputfilename , "w" );
			fprintf(outputfile,"######");
			fclose(outputfile);
		}
	}
	else{
		//printf("here\n");
		remove(filename_readin);
		remove(outputfilename);
		remove(outputfilename_temp);
		FILE* outputfile = fopen( outputfilename , "w" );
		fprintf(outputfile,"######");
		fclose(outputfile);
	}

	exit(EXIT_SUCCESS);
}
