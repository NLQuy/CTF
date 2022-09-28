#include <stdio.h>;
#include <stdlib.h>


struct trooper {
	char name[0x8];
	int damn;
	int health;
};

struct hero {
	int fame_id;
	char name[0x10];
	int damn;
	int special_damn;
	int health;
};

struct monster {
	size_t monster_sign;
	int damn;
	int bonus_damn;
	int health;
};

void print_info_hero(struct hero hr)    {
	printf("======= %s =======\n", hr.name);
	printf("\t[*] Total damn (damn + special_damn): %d\n", hr.damn+hr.special_damn);
	printf("\t[*] Health: %d\n", hr.health);
	printf("==================\n");
}


void print_info_monster(struct monster mst) {
	puts(mst.monster_sign);
	printf("======= %llx =======\n", mst.monster_sign);
	printf("\t[*] Total damn (damn + bonus_damn): %d\n", mst.damn+mst.bonus_damn);
	printf("\t[*] Health: %d\n", mst.health);
	printf("==================\n");
}

void print_info_trooper(struct trooper mst) {
	printf("======= %s =======\n", mst.name);
	printf("\t[*] Total damn (damn + bonus_damn): %d\n", mst.damn);
	printf("\t[*] Health: %d\n", mst.health);
	printf("==================\n");
}

void print_hall_of_fame(char *hallofame[0x10])  {
	printf("======= ^ HALL OF FAME ^ =======\n");
	for (int i = 0; i < 0x5; i++)   {
		/*printf("[%d] - ", i);*/
		puts(hallofame[i]);
	}
}

void hero_turn()	{
	printf("========================\n");
	printf("\t\t âš§ Hero turn \n");
	printf("========================\n");
}

void trooper_turn()	{
	printf("========================\n");
	printf("\t\t âš¨ Trooper turn \n");
	printf("========================\n");
}

void monster_turn()	{
	printf("========================\n");
	printf("\t\t â˜  Monster turn \n");
	printf("========================\n");
}

void hero_info(struct hero hr[2])	{
	for(int i = 0; i < 2; i++)	{
		printf("============== HERO %d ===============\n", i);
		printf("[+] Damn: %d\n", hr[i].damn);
		printf("[+] Health: %d\n", hr[i].health);
		printf("[+] Hall of Fame: %d\n", hr[i].fame_id);
		printf("======================================\n\n");
	}
}

void monster_info(struct monster hr[2])	{
	for(int i = 0; i < 2; i++)	{
		printf("============== Monster %d ===============\n", i);
		printf("[+] Damn: %d\n", hr[i].damn);
		printf("[+] Health: %d\n", hr[i].health);
		printf("======================================\n\n");
	}
}

void trooper_info(struct trooper hr[2])	{
	for(int i = 0; i < 5; i++)	{
		printf("============== %s ===============\n", hr[i].name);
		printf("[+] Damn: %d\n", hr[i].damn);
		printf("[+] Health: %d\n", hr[i].health);
		printf("======================================\n\n");
	}
}

void monster_won()	{
	printf("â–ˆâ–€â–„â–€â–ˆ â–ˆâ–€â–€â–ˆ â–ˆâ–€â–€â–„ â–ˆâ–€â–€ â–€â–€â–ˆâ–€â–€ â–ˆâ–€â–€ â–ˆâ–€â–€â–ˆ   â–ˆâ–‘â–‘â–‘â–ˆ â–ˆâ–€â–€â–ˆ â–ˆâ–€â–€â–„ â–ˆ\n");
	printf("â–ˆâ–‘â–€â–‘â–ˆ â–ˆâ–‘â–‘â–ˆ â–ˆâ–‘â–‘â–ˆ â–€â–€â–ˆ â–‘â–‘â–ˆâ–‘â–‘ â–ˆâ–€â–€ â–ˆâ–„â–„â–€   â–ˆâ–„â–ˆâ–„â–ˆ â–ˆâ–‘â–‘â–ˆ â–ˆâ–‘â–‘â–ˆ â–€\n");
	printf("â–€â–‘â–‘â–‘â–€ â–€â–€â–€â–€ â–€â–‘â–‘â–€ â–€â–€â–€ â–‘â–‘â–€â–‘â–‘ â–€â–€â–€ â–€â–‘â–€â–€   â–‘â–€â–‘â–€â–‘ â–€â–€â–€â–€ â–€â–‘â–‘â–€ â–„\n");
}

void hero_won()	{
	printf("â”â”“ï¸±ï¸± ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸±   ï¸±ï¸±ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸±\n");
	printf("â”ƒâ”ƒï¸±ï¸± ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸±   ï¸±ï¸±ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸± ï¸±ï¸±ï¸±ï¸±\n");
	printf("â”ƒâ”—â”â”“ â”â”â”â”“ â”â”â”“ â”â”â”â”“   â”â”“â”â”“â”â”“ â”â”â”â”“ â”â”â”“ï¸±\n");
	printf("â”ƒâ”â”“â”ƒ â”ƒâ”ƒâ”â”« â”ƒâ”â”› â”ƒâ”â”“â”ƒ   â”ƒâ”—â”›â”—â”›â”ƒ â”ƒâ”â”“â”ƒ â”ƒâ”â”“â”“\n");
	printf("â”ƒâ”ƒâ”ƒâ”ƒ â”ƒâ”ƒâ”â”« â”ƒâ”ƒï¸± â”ƒâ”—â”›â”ƒ   â”—â”“â”â”“â”â”› â”ƒâ”—â”›â”ƒ â”ƒâ”ƒâ”ƒâ”ƒ\n");
	printf("â”—â”›â”—â”› â”—â”â”â”› â”—â”›ï¸± â”—â”â”â”›   ï¸±â”—â”›â”—â”›ï¸± â”—â”â”â”› â”—â”›â”—â”›\n");
}

int gameon(struct hero hr[2], struct trooper trp[5], struct monster mst[5], int isvictory)  {
	int gameon = 1;
	int choice;
	int guess;
	int hero_idx = 0;
	int monster_idx = 0;
	int trooper_idx = 0;

	srand(0x1337);
	while(gameon)	{
		hero_info(hr);
		trooper_info(trp);
		monster_info(mst);

		//check alive hero
		for(hero_idx = 0; hero_idx < 2; hero_idx++)	{
			if(hr[hero_idx].health > 0)	{
				break;
			}
		}

		//check alive monster
		for(monster_idx = 0; monster_idx < 2; monster_idx++)	{
			if(mst[monster_idx].health > 0)	{
				break;
			}
		}

		//check alive trooper
		for(trooper_idx = 0; trooper_idx < 5; trooper_idx++)	{
			if(trp[trooper_idx].health > 0)	{
				break;
			}
		}
		
		hero_turn();
		printf("Do you wanna attack [1]monster or [0]trooper?(1/0)\n");
		scanf("%d", &choice);
		if(choice == 1) { //Attack Monster
			printf("Attacking the monster....\n");
			int monster_ad = rand() % 2022;
			printf("Guessing monster attack direction to attack\nWhat do you think? > ");
			scanf("%d", &guess);
			if(guess == monster_ad)	{
				printf("Monster is lack %d healths!\n", (hr[hero_idx].damn + hr[hero_idx].special_damn));
				mst[monster_idx].health -= (hr[hero_idx].damn + hr[hero_idx].special_damn);
			}
			else {
				printf("Monster blocked your attack!\n");
			}
			if(mst[monster_idx].health < 0)	{
				mst[monster_idx].health = 0;
			}
		}
		else if (choice == 0) {
			if(trooper_idx > 4)	{
				printf("There is no trooper :(\n");
			} else {
				printf("Kill by yourself your trooper :( \n");
				trp[trooper_idx].health -= hr[hero_idx].damn;
				if(trp[trooper_idx].health <= 0 && trooper_idx < 5)	{
					hr[hero_idx].fame_id += 4; // Decrease hall of fame
				}
			}
		}
		else {
			printf("Unknown target. Please choice 1 or 0\n");
		}

		if(mst[monster_idx].health <= 0 && monster_idx > 1 && hero_idx < 2)	{ //win game 
			gameon = 0;
			hr[hero_idx].fame_id -= 2;
			isvictory = 1;
			hero_won();
		}

		trooper_turn();
		if(trooper_idx < 5)	{
			printf("Attacking the monster ...\n");
			mst[monster_idx].health -= trp[trooper_idx].damn;
		}

		if(mst[monster_idx].health < 0)	{
			mst[monster_idx].health = 0;		
		}

		monster_turn();
		if(hero_idx < 2) {
			printf("Attack the hero first! Kill the legion commander\n");
			hr[hero_idx].health -= (mst[monster_idx].damn);
		} else if(hero_idx < 2 && trooper_idx < 5) {
			printf("Kill last troopers!\n");
			trp[trooper_idx].health = 0;
		}
		if(hr[hero_idx].health < 0 && hero_idx > 1 || hero_idx > 1)	{
			gameon = 0;
			monster_won();
			isvictory = 0;
		}
	}

	return isvictory;
}

int agiftfromkma()  {
	FILE *fp;
	char flag[41];
	memset(flag, 0, 41);
	fp = fopen("./flag.txt", "rb");
	int count = fread(&flag, sizeof(char), 40, fp);
	fclose(fp);

	printf("Here is your gift: %s\n", flag);

	return 0;
}

void banner()	{
	printf(" â–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆâ–ˆ  â–ˆ   â–ˆ â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆâ–ˆ  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ â–ˆ  â–ˆ  â–ˆ   â–ˆ  â–ˆâ–ˆâ–ˆ  \n");
	printf("â–ˆ     â–ˆ   â–ˆ â–ˆâ–ˆ â–ˆâ–ˆ â–ˆ     â–ˆ   â–ˆ â–ˆ     â–ˆ â–ˆ   â–ˆâ–ˆ â–ˆâ–ˆ â–ˆ   â–ˆ \n");
	printf("â–ˆ  â–ˆâ–ˆ â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ â–ˆ â–ˆ â–ˆ â–ˆâ–ˆâ–ˆâ–ˆ  â–ˆ   â–ˆ â–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆ â–ˆ  â–ˆ â–ˆ â–ˆ â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ \n");
	printf("â–ˆ   â–ˆ â–ˆ   â–ˆ â–ˆ   â–ˆ â–ˆ     â–ˆ   â–ˆ â–ˆ     â–ˆ  â–ˆ  â–ˆ   â–ˆ â–ˆ   â–ˆ \n");
	printf(" â–ˆâ–ˆâ–ˆ  â–ˆ   â–ˆ â–ˆ   â–ˆ â–ˆâ–ˆâ–ˆâ–ˆâ–ˆ  â–ˆâ–ˆâ–ˆ  â–ˆ     â–ˆ   â–ˆ â–ˆ   â–ˆ â–ˆ   â–ˆ \n");
	printf("\t\t -Author: h4niz -\n");
}

void endgame()	{
	printf("\n\n");
	printf(" ========== ð—•ð—¬ð—˜ ==========\n");
}
int main()  {
	char halloframe[0x5][0x10];
	char leak[2][0x8];
	struct monster  mst[0x5];
	struct trooper trp[0x5];
	struct hero hr[2];

	memset(halloframe, 0, sizeof(halloframe));
	memset(leak, 0, sizeof(leak));
	memset(mst, 0, sizeof(mst));
	memset(trp, 0, sizeof(trp));
	memset(hr, 0, sizeof(hr));

	int isvictory = 0;
	int tmp = 0;
	int numhero;

	printf("Initiating game ...\n");
	printf("How many trooper(s) do you want?(0-5)\n");
	scanf("%d", &tmp);
	for(int i = 0; i < tmp; i++)    {
		snprintf(trp[i].name, sizeof(trp[i].name), "Trooper%d", i);
		trp[i].damn = 0x10;
		trp[i].health = 0x20;
		print_info_trooper(trp[i]);
	}

	printf("How many monster do you want?(0-2)\n");
	scanf("%d", &tmp);
	for(int i =0; i<tmp; i++)   {
		mst[i].monster_sign = leak[0x33];
		mst[i].damn = 0x20;
		mst[i].bonus_damn = 0x10;
		mst[i].health = 0x100;

		print_info_monster(mst[i]);
	}

	printf("How many hero do you want?(0-2)\n");
	scanf("%d", &numhero);
	for(int i =0; i<numhero; i++)   {
		hr[i].fame_id = i;
		hr[i].damn = 0x20;
		hr[i].special_damn = 0x30;
		hr[i].health = 0x200;

		printf("How do you call your hero?\n");
		read(0, hr[i].name, sizeof(hr[i].name));
		print_info_hero(hr[i]);
	}

	banner();
	isvictory = gameon(hr, trp, mst, &isvictory);

	if(isvictory)   {
		printf("Big won! The civilian always remember heroes!\n");
		printf("======== ^ HALL OF FAME ^ =========\n");
		for(int i =0; i < numhero; i++) {
			memcpy(halloframe[hr[i].fame_id], hr[i].name, sizeof(hr[i].name));
			if(hr[i].fame_id < 0)	{
				hr[i].fame_id = 0;
			}
			printf("Top %d - %s\n", (hr[i].fame_id+1), hr[i].name);
		}
	}

	endgame();
	return 0;
}