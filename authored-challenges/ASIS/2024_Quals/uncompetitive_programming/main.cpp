#include <iostream>
#include <cstdint>
#include <cstring>
using namespace std;

#define SEG_SIZE 0x80
#define FEN_SIZE 0x40

class SegNode {
private:
	uint8_t fen[FEN_SIZE];
	SegNode *left;
	SegNode *right;
public:
	inline void create_child(SegNode **child_slot) {
		if (*child_slot == NULL) {
			*child_slot = new SegNode;
			(*child_slot)->left = NULL;
			(*child_slot)->right = NULL;
			memset((*child_slot)->fen, 0, sizeof(uint8_t)*FEN_SIZE);
		}
	}

	void seg_add(int i, int j, uint8_t x, int l = 0, int r = SEG_SIZE - 1) {
		fen_add(j, x);
		if (l == r) return;
		int mid = (r + l) / 2;
		if (i <= mid) {
			create_child(&left);
			left->seg_add(i, j, x, l, mid);
		} else {
			create_child(&right);
			right->seg_add(i, j, x, mid + 1, r);
		}
	}

	uint8_t seg_get(int r1, int c1, int r2, int c2, int l = 0, int r = SEG_SIZE - 1) {
		if (l > r2 || r < r1) return 0;
		if (l >= r1 && r <= r2) return fen_get(c1, c2);
		int mid = (r + l) / 2;
		uint8_t res = 0;
		if (left != NULL) res ^= left->seg_get(r1, c1, r2, c2, l, mid);
		if (right != NULL) res ^= right->seg_get(r1, c1, r2, c2, mid + 1, r);
		return res;
	}

	// returns if we should delete the current node in the parent call
	bool seg_del(int i, int l = 0, int r = SEG_SIZE - 1) {
		if (l == r)
			return true;
		int mid = (r + l) / 2;
		if (i <= mid) {
			if (left == NULL) return (right == NULL);
			if (left->seg_del(i, l, mid)) {
				delete left;
				return (right == NULL);
			}
		} else {
			if (right == NULL) return (left == NULL);
			if (right->seg_del(i, mid + 1, r)) {
				delete right;
				return (left == NULL);
			}
		}
		return false;
	}

	void fen_add(int i, uint8_t x) {
		for (i++; i <= FEN_SIZE; i += i & -i)
			fen[i - 1] ^= x;
	}

	uint8_t fen_get(int i) {
		uint8_t res = 0;
		for (i++; i > 0; i -= i & -i)
			res ^= fen[i - 1];
		return res;
	}

	uint8_t fen_get(int l, int r) {
		return fen_get(r) ^ fen_get(l - 1);
	}

#ifdef DEBUG
	// void debug_print(int l = 0, int r = SEG_SIZE - 1, int level = 0) {
	// 	for (int i = 0; i < level; i++) cout << '\t';
	// 	cout << "(" << l << ", " << r << "): ";
	// 	if (left != NULL) cout << 'L';
	// 	if (right != NULL) cout << 'R';
	// 	cout << ' ';
	// 	for (int i = 0; i < FEN_SIZE; i++) {
	// 		cout << (unsigned int)fen_get(i, i) << ' ';
	// 	}
	// 	cout << endl;
	// 	int mid = (r + l) / 2;
	// 	if (left != NULL) left->debug_print(l, mid, level + 1);
	// 	if (right != NULL) right->debug_print(mid + 1, r, level + 1);
	// }
#endif
};

SegNode segroot;

void disable_io_buffering(void) {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void menu_add(int r1, int c1, uint8_t x) {
	if (r1 < 0 || r1 >= SEG_SIZE || c1 < 0 || c1 >= FEN_SIZE) {
		cout << "Nope" << endl;
		return;
	}
	segroot.seg_add(r1, c1, x);
}

void menu_get(int r1, int c1, int r2, int c2) {
	if (r1 < 0 || r1 >= SEG_SIZE || r2 < 0 || r2 >= SEG_SIZE
		|| c1 < 0 || c1 >= FEN_SIZE || c2 < 0 || c2 >= FEN_SIZE
		|| r1 > r2 || c1 > c2) {
			cout << "Nope" << endl;
			return;
		}
	unsigned int result = segroot.seg_get(r1, c1, r2, c2);
	cout << "Result: " << result << endl;
}

void menu_del(int r1) {
	if (r1 < 0 || r1 >= SEG_SIZE) {
		cout << "Nope" << endl;
		return;
	}
	segroot.seg_del(r1);
}

int main(void) {
	disable_io_buffering();
	// while (true) {
	// TODO: limit the number of interactions?
	for (int i = 0; i < 250; i++) {
		char c;
		int r1, c1, r2, c2;
		unsigned int x;
		cout << "> ";
		cin >> c;
		switch (c) {
			case '+':
				cin >> r1 >> c1 >> x;
				menu_add(r1, c1, x);
				break;
			case '?':
				cin >> r1 >> c1 >> r2 >> c2;
				menu_get(r1, c1, r2, c2);
				break;
			case 'x':
				cin >> r1;
				menu_del(r1);
				break;
			default:
				cout << "Invalid option!" << endl;
				return 1;
		}
#ifdef DEBUG
		// segroot.debug_print();
#endif
	}
	return 0;
}
