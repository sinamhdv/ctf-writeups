#include <bits/stdc++.h>
using namespace std;

#define BOARD_SIZE 0x20

typedef pair<unsigned char, unsigned char> pcc;

basic_string<wchar_t> flag0 = "placeholder for first flag";
basic_string<wchar_t> flag1 = "placeholder for second flag";
basic_string<wchar_t> theend = "cat notflag";

// some static helper functions
class Helper
{
public:
	static set<wchar_t> letters({'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'});
	static set<wchar_t> digits({'0','1','2','3','4','5','6','7','8','9'});

	static wchar_t getCharOrQ(wchar_t input_char) {
		if (letters.find(input_char) == letters.end() && digits.find(input_char) == digits.end())
			return '?';
		return input_char;
	}

	static string getSubstrAfterLastQ(string str) {
		// TODO
	}

	static string getSubstrBeforeFirstQ(string str) {
		// TODO
	}

	static vector<Object *> getWall(unsigned char x, unsigned char y, unsigned char length, char dir) {
		vector<Object *> result;
		if (dir == 'h')
			for (int i = 0; i < length; i++)
				result.emplace_back(x + i, y, NONE, '▦', "wall");
		else if (dir == 'v')
			for (int i = 0; i < length; i++)
				result.emplace_back(x, y + i, NONE, '▦', "wall");
	}

	static vector<Object *> genWalls(unsigned char x1, unsigned char y1, unsigned char x2, unsigned char y2) {
		// creates walls with a rectangle shape with top-left corner at (x1,y1) and bottom-right corner at (x2,y2)
		// TODO
	}

	// TODO
};

enum ObjectType {
	NONE = 3,	// no type
	YOU = 2,	// controlled by you
	PUSH = 1,	// you can push it around
	STOP = 0,	// you can't move past this object
	WIN = 5,	// you will win by moving on these objects
	MELT = 4	// any object that moves onto a melt object will be destroyed
}

// An abstract class which is the parent of Object and
// thus some of object's functions are virtual. However,
// this class is never used and it doesn't contain seperate
// implementation for those virtual functions itself.
class GameObject
{
};

/*
vtable for Object + 16:
   getSymbol
   getObjectType
   move
   getX
   getY
   ~Object
   ~Object
*/

class Object : public GameObject
{
private:	// These fields can be entered into Ghidra struct editor to make the decompilation more clear
	// func *vptr;
	unsigned char x;
	unsigned char y;
	// padding[2]
	ObjectType objectType;
	wchar_t symbol;
	// padding[4]
	string objectName;

public:
	virtual unsigned char getX() { return x; }
	virtual unsigned char getY() { return y; }
	virtual ObjectType getObjectType() { return objectType; }
	virtual wchar_t getSymbol() { return symbol; }
	string &getObjectName() { return objectName; }
	void setObjectName(string objectName) { this->objectName = objectName; }
	void setObjectType(string objectType) { this->objectType = objectType; }
	
	string getObjAt() {
		basic_stringstream ss(???);
		ss << "0x" << hex << (uint64_t)this;
		return getObjectName() + "at" + ss.str();
	}

	virtual void move(wchar_t dir) {
		if (dir == 'd') x = min(x + 1, BOARD_SIZE - 1);
		else if (dir == 'a') x = max(x - 1, 0);
		else if (dir == 's') y = min(y + 1, BOARD_SIZE - 1);
		else if (dir == 'w') y = max(y - 1, 0);
	}
};

class Game
{
	// a map whose keys represents (x, y) coordinate pairs of the game board and
	// for each coordinate we have a vector of objects in that cell.
	map<pcc, vector<Object *>> objectsMap;

	Game(void) { initMap(); }
	
	void initMap(void) {
		for (unsigned char i = 0; i < BOARD_SIZE; i++) {
			for (unsigned char j = 0; j < BOARD_SIZE; j++) {
				vector<Object *> tmp_vec;
				map[{i, j}] = tmp_vec;
			}
		}
	}

	map<pcc, vector<Object *>> &getObjectsMap(void) { return objectsMap; }

	void init(vector<Object *> &vector_of_objects) {
		for (Object *obj : vector_of_objects)
			this->add(obj);
	}

	// add an object to the game
	void add(Object *obj) {
		unsigned char x = obj->getX();
		unsigned char y = obj->getY();
		objectsMap[{x, y}].insert(objectsMap[{x, y}].begin(), obj);
	}

	// print the game board
	void display(void) {
		// TODO
	}

	// scan for phrases of the form 'XatY' on the game board
	map<string, uint64_t> scanAt(void) {
		map<string, uint64_t> result;

		// scan vertically
		for (unsigned char i = 0; i < BOARD_SIZE; i++) {
			vector<string> segments;
			string segment;
			for (unsigned char j = 0; j < BOARD_SIZE; j++) {
				auto iterator = objectsMap.find({j, i});
				if (iterator == objectsMap.end() || (iterator->second).empty()) {
					if (!segment.empty()) {
						segments.push_back(segment);
						segment.clear();
					}
				}
				else if ((iterator->second).size() < 2) {
					segment += Helper::getCharOrQ(iterator->second.back()->getSymbol());
				}
				else {
					segment += "?";
				}
			}
			for (string seg : segments)
				this->scanAtInSegment(seg, result);
		}
		
		// scan horizontally
		for (unsigned char i = 0; i < BOARD_SIZE; i++) {
			vector<string> segments;
			string segment;
			for (unsigned char j = 0; j < BOARD_SIZE; j++) {
				auto iterator = objectsMap.find({i, j});	// the only difference between the 2 main loops in this function
				if (iterator == objectsMap.end() || (iterator->second).empty()) {
					if (!segment.empty()) {
						segments.push_back(segment);
						segment.clear();
					}
				}
				else if ((iterator->second).size() < 2) {
					segment += Helper::getCharOrQ(iterator->second.back()->getSymbol());
				}
				else {
					segment += "?";
				}
			}
			for (string seg : segments)
				this->scanAtInSegment(seg, result);
		}

		return result;
	}

	// look for 'XatY' phrase in a non-whitespace segment of the game board
	void scanAtInSegment(string segment, map<string, uint64_t> &result) {
		basic_regex<wchar_t> pattern("(.+)at(0x[0-9a-fA-F]+)", regex::ECMAScript);
		regex_iterator first_match_iter(segment.begin(), segment.end(), pattern), end_iter;
		for (regex_iterator match_iter = first_match_iter; match_iter != end_iter; match_iter++) {
			match_results match = *match_iter;
			string name = match[1].str();
			string addr_str = match[2].str();
			uint64_t address = stoull(addr_str, 0, 16);
			result[name] = address;
		}
	}

	// scan for 'XisY' phrases on the game board
	// returns map of each ObjectType with a vector of object names of that type
	map<ObjectType, vector<string>> scanIs(void) {
		map<ObjectType, vector<string>> result;

		// scan vertically
		for (unsigned char i = 0; i < BOARD_SIZE; i++) {
			vector<string> segments;
			string segment;
			for (unsigned char j = 0; j < BOARD_SIZE; j++) {
				auto iterator = objectsMap.find({j, i});
				if (iterator == objectsMap.end() || (iterator->second).empty()) {
					if (!segment.empty()) {
						segments.push_back(segment);
						segment.clear();
					}
				}
				else if ((iterator->second).size() < 2) {
					segment += Helper::getCharOrQ(iterator->second.back()->getSymbol());
				}
				else {
					segment += "?";
				}
			}
			for (string segment : segments) {
				basic_regex<wchar_t> pattern("(.+)is(.+)", regex::ECMAScript);	// XXX does this match to the end of the segment?
				regex_iterator first_match_iter(segment.begin(), segment.end(), pattern), end_iter;
				for (regex_iterator match_iter = first_match_iter; match_iter != end_iter; match_iter++) {
					match_results match = *match_iter;
					string part1 = match[1];
					string part2 = match[2];
					string type_str = Helper::getSubstrBeforeFirstQ(part2);
					ObjectType type = 3;
					if (type_str == "u") type = 2;
					else if (type_str == "push") type = 1;
					else if (type_str == "stop") type = 0;
					else if (type_str == "win") type = 5;
					else if (type_str == "melt") type = 4;
					string name = Helper::getSubstrAfterLastQ(part1);
					result[type].push_back(name);
				}
			}
		}

		// scan horizontally
		for (unsigned char i = 0; i < BOARD_SIZE; i++) {
			vector<string> segments;
			string segment;
			for (unsigned char j = 0; j < BOARD_SIZE; j++) {
				auto iterator = objectsMap.find({i, j});	// the only different line between the 2 main loops of this function
				if (iterator == objectsMap.end() || (iterator->second).empty()) {
					if (!segment.empty()) {
						segments.push_back(segment);
						segment.clear();
					}
				}
				else if ((iterator->second).size() < 2) {
					segment += Helper::getCharOrQ(iterator->second.back()->getSymbol());
				}
				else {
					segment += "?";
				}
			}
			for (string segment : segments) {
				basic_regex<wchar_t> pattern("(.+)is(.+)", regex::ECMAScript);
				regex_iterator first_match_iter(segment.begin(), segment.end(), pattern), end_iter;
				for (regex_iterator match_iter = first_match_iter; match_iter != end_iter; match_iter++) {
					match_results match = *match_iter;
					string part1 = match[1];
					string part2 = match[2];
					string type_str = Helper::getSubstrBeforeFirstQ(part2);
					ObjectType type = 3;
					if (type_str == "u") type = 2;
					else if (type_str == "push") type = 1;
					else if (type_str == "stop") type = 0;
					else if (type_str == "win") type = 5;
					else if (type_str == "melt") type = 4;
					string name = Helper::getSubstrAfterLastQ(part1);
					result[type].push_back(name);
				}
			}
		}

		return result;
	}

	// XXX what happens if I enter something not W/A/S/D?
	void move(wchar_t input) {
		vector<Object *> movable_objects;
		for (pair<pcc, vector<Object *>> &p : objectsMap) {
			for (Object *obj : p.second) {
				if (obj->getObjectType() == YOU) {
					movable_objects.push_back(obj);
				}
			}
		}
		
		for (Object *obj : movable_objects) {
			Object after_move_obj = *obj;
			after_move_obj.move(input);
			bool do_move = true;

			for (pair<pcc, vector<Object *>> &p : objectsMap) {
				for (Object *target : p.second) {
					if (target->getX() == after_move_obj.getX() && target->getY() == after_move_obj.getY()) {
						if (target->getObjectType() == PUSH) {
							if (isStopped(target, input)) {
								do_move = false;
								break;
							}
						}
						else if (target->getObjectType() == STOP &&
								target->getX() == after_move_object.getX() &&
								target->getY() == after_move_object.getY()) {
							do_move = false;
							break;
						}
					}
				}
			}
			
			if (do_move) {
				remove(obj);
				obj->move(input);
				add(obj);
			}

			// XXX this will happen even if do_move == false
			for (pair<pcc, vector<Object *>> &p : objectsMap) {
				for (Object *target : p.second) {
					if (target != obj && target->getX() == obj->getX() && target->getY() == obj->getY() &&
							target->getObjectType() == PUSH && !isStopped(target, input)) {
						remove(target);
						moveNext(target, input);
					}
				}
			}
		}
	}

	void remove(Object *obj) {
		for (pair<pcc, vector<Object *>> &p : objectsMap) {
			vector<Object *> &vec = p.second;
			auto iter = remove_if(vec.begin(), vec.end(), [obj](Object *ptr){ return obj == ptr; });
			vec.erase(iter, vec.end());
		}
	}

	bool isStopped(Object *obj, wchar_t dir) {
		int x = obj->getX();
		int y = obj->getY();
		int targetX = x, targetY = y;
		if (dir == 'd') targetX = min(BOARD_SIZE - 1, targetX + 1);
		else if (dir == 'a') targetX = max(0, targetX - 1);
		else if (dir == 's') targetY = min(BOARD_SIZE - 1, targetY + 1);
		else if (dir == 'w') targetY = max(0, targetY - 1);
		
		if ((targetX == x && (dir == 'a' || dir == 'd')) || (targetY == y && (dir == 's' || dir == 'w')))
			return true;
		
		map<pcc, vector<Object *>> map_clone = objectsMap;
		for (Object *obj2 : map_clone[{targetX, targetY}])
			if (obj2->getObjectType() == STOP)
				return true;
		
		for (Object *obj2 : map_clone[{targetX, targetY}])
			if (obj2->getObjectType() == PUSH && obj2 != obj)
				return isStopped(obj2, dir);

		return false;
	}

	void moveNext(Object *obj, wchar_t dir) {
		obj->move(dir);
		add(obj);
		for (Object *nextObj : objectsMap[{obj->getX(), obj->getY()}]) {
			if (nextObj != obj && nextObj->getObjectType() == PUSH) {
				remove(nextObj);
				moveNext(nextObj, dir);
			}
		}
	}

	bool checkForWin(void) {
		for (pair<pcc, vector<Object *>> &p : objectsMap) {
			vector<Object *> &map_cell = p.second;
			for (Object *obj : map_cell) {
				if (obj->getObjectType() == YOU) {
					auto iter = find_if(map_cell.begin(), map_cell.end(), [](Object *ptr){ return ptr->getObjectType() == WIN; });
					if (iter != map_cell.end() && (*iter)->getX() == obj->getX() && (*iter)->getY() == obj->getY()) {
						if ((*iter)->getSymbol() == '►')
							cout << flag0 << endl;
						else if ((*iter)->getSymbol() == '◄')
							cout << flag1 << endl;
						return true;
					}
				}
			}
		}
		return false;
	}

	void removeMelted(void) {
		for (pair<pcc, vector<Object *>> &p : objectsMap) {
			bool hasMelter = false;
			for (Object *obj : p.second)
				if (obj->getObjectType() == MELT)
					hasMelter = true;
			
			if (hasMelter) {
				for (Object *obj : p.second) {
					if (obj->getObjectType() != MELT) {
						// XXX VULN: removing from a vector as we are in a for-each on the same vector.
						// If there are two adjacent elements in the vector both with objectType != MELT,
						// only the first one will be removed and the second one will not be melted and can go
						// past the melter obstacle in the next turn!
						remove(obj);
					}
				}
			}
		}
	}

	vector<Object *> getObjectsByName(string name) {
		// TODO
	}
};

void alarmHandler(int sig) {
	// also converts theend from utf-8 to ascii before calling c_str() and system()
	system(theend.c_str());
}

int main(void)
{
	signal(SIGALRM, alarmHandler);
	alarm(20);

	// TODO: init some Objects on the stack
	// TODO: make an array of pointers to the Objects (array_of_objects)
	vector<Object *> vector_of_objects(array_of_objects);
	
	// init walls:
	vector<Object *> walls1 = Helper::genWall(0x15, 0x3, 0x12, 'v');
	for (Object *obj : walls1) vector_of_objects.push_back(obj);
	vector<Object *> walls2 = Helper::genWall(3, 0x14, 0x11, 'h');
	for (Object *obj : walls2) vector_of_objects.push_back(obj);
	vector<Object *> walls3 = Helper::genWalls(2, 2, 0x1c, 0x1c);
	for (Object *obj : walls3) vector_of_objects.push_back(obj);

	// TODO: init letter objects of 'XisY' phrases

	// init 'babaat0x...' phrase:
	string baba_at_phrase = baba_object.getObjAt();

	// TODO: use Helper::genAlNum(...) to generate alphanumeric objects for the phrase

	Game game;
	game.init(vector_of_objects);
	while (true)
	{
		game.display();
		map<pcc, vector<Object *>> &objectsMap = game.getObjectsMap();

		for (pair<pcc, vector<Object *>> gameBoardCell : objectsMap)
			for (Object* obj : gameBoardCell.second)
				obj->setObjectType(NONE);

		map<string, uint64_t> at_strings = game.scanAt();
		for (pair<string, uint64_t> &obj_info : at_strings) {
			string obj_name = obj_info.first;
			uint64_t obj_address = obj_info.second;
			// XXX VULN: can change the content of an arbitrary string object
			// by having its address
			((Object *)obj_address)->setObjectName(obj_name);
		}

		map<ObjectType, vector<string>> is_strings = game.scanIs();
		for (pair<ObjectType, vector<string>> &p : is_strings) {
			for (string &name : p.second) {
				vector<Object *> objects = game.getObjectsByName(name);
				for (Object *obj : objects)
					obj->setObjectType(p.first);
			}
		}

		wchar_t moveInput;
		wcin >> moveInput;
		game.move(moveInput);
		game.checkForWin();
		game.removeMelted();
	}
	return 0;
}

