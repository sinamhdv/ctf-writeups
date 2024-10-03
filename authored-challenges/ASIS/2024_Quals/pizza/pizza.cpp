#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>
using namespace std;

#define MAXN 0x100

vector<int> graph[MAXN];
int dist[MAXN];

class Queue
{
private:
	uint8_t arr[64];
	uint16_t tail;
	uint16_t head;
public:
	Queue() { head = tail = 0; }
	void push_back(uint8_t x) { arr[tail++] = x; }
	void pop_front() { head++; if (head == tail) head = tail = 0; }
	uint8_t front() { return arr[head]; }
	bool empty() { return head == tail; }
};

void disable_io_buffering(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void find_path(int src, int dst)
{
	long long parent[0x100];
	Queue q;
	q.push_back(src);
	dist[src] = 0;
	
	while (!q.empty())
	{
		int v = q.front();
		q.pop_front();
		for (int u : graph[v])
		{
			if (dist[v] + 1 <= dist[u])
			{
				dist[u] = dist[v] + 1;
				parent[u] = v;
				q.push_back(u);
			}
		}
	}

	cout << "Result:" << endl;
	vector<long long> path;
	long long current_v = dst;
	while (current_v != src && current_v >= 0 && current_v < MAXN)
	{
		path.push_back(current_v);
		current_v = parent[current_v];
	}
	path.push_back(current_v);
	reverse(path.begin(), path.end());
	for (int i = 0; i < (int)path.size(); i++)
	{
		cout << "(" << path[i] << ")";
		if (i != (int)path.size() - 1)
			cout << " -> ";
	}
	cout << endl << endl;
}

int main(void)
{
	disable_io_buffering();
	cout << "Welcome to the world's best pizza delivery assistant!" << endl;
	while (1)
	{
		for (int i = 0; i < MAXN; i++)
			graph[i].clear();
		fill(dist, dist + MAXN, 1000000000);

		int edges = 0;
		cout << "Describe your city: ";
		cin >> edges;
		
		for (int i = 0; i < edges; i++)
		{
			int x = -1, y = -1;
			while (true)
			{
				// cout << "Enter the endpoints of street #" << (i + 1) << ": ";
				cout << "> ";
				cin >> x >> y;
				if (x < 0 || x >= MAXN || y < 0 || y >= MAXN)
					cout << "Nope" << endl;
				else
					break;
			}
			graph[x].push_back(y);
			graph[y].push_back(x);
		}

		int src, dst;
		cout << "Where is the restaurant? ";
		cin >> src;
		cout << "Where is the client? ";
		cin >> dst;
		find_path(src, dst);
	}
	return 0;
}
