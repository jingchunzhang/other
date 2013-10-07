#include <stdio.h>
#include <math.h>

int src[] = {1, 2, 3, 4, 5, 6, 7, 8};

int main()
{
	int n = sizeof(src)/sizeof(int);

	int max = (int)pow((double)2, (double)n);

	printf("%d %d\n", n, max);

	int i = 1;

	int mod, di;

	while (i < max)
	{
		n = 0;

		di = i;
		while (1)
		{
			mod = di%2;
			if (mod)
				printf("%d ", src[n]);
			di = di/2;
			if (di == 0)
				break;
			n++;
		}
		printf("\n");
		i++;
	}

	return 0;
}
