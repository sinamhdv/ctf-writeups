#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

int main(void)
{
	setup();
	srand((unsigned int)main);	// PIE must be on

	puts("This game is so easy!");
	puts("Just guess the correct number to win!");
	puts("If you lose 3 times you'll be kicked out");

	struct {
		char input[2048];
		char lives[4];
		int money;
	} game_data = {"", "***", 1000};

	memset(game_data.input, 0, sizeof(game_data.input));

	while (1) {
		printf("\nLives: %s\nYour money: %d\n", game_data.lives, game_data.money);

		if (game_data.money < 0) {
			puts("You can't play anymore :(");
			break;
		}

		printf("Enter a bet value: ");
		int your_bet = -1;
		scanf("%d", &your_bet);
		if (your_bet <= 0) {
			puts("Your bet amount should be positive!");
			continue;
		}

		int my_bet = rand() % 100 + 1;
		printf("Your bet: %d, my bet: %d\n", your_bet, my_bet);

		printf("Enter your guess: ");
		int guess = -1;
		scanf("%d", &guess);
		getchar();
		int random_num = rand() % 1000 + 1;
		
		if (random_num == guess) {
			puts("You won!");
			game_data.money += my_bet;
		}
		else {
			puts("You lost :(");
			game_data.money -= your_bet;
			game_data.lives[strlen(game_data.lives) - 1] = 0;
		}

		if (game_data.money + 1 < sizeof(game_data.input)) {
			printf("Please give us your feedback for this round: ");
			read(0, game_data.input, (unsigned int)game_data.money);
			puts("Thanks for your feedback!");
		}
		else {
			puts("Sorry we can't take your feedback this time");
		}
		
		if (strlen(game_data.lives) == 0) {
			puts("No more lives");
			break;
		}
	}

	puts("Bye!");

	return 0;
}
