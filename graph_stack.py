from matplotlib import pyplot as plt

path = 'gdb.txt.stack2'


def main():
    data = []
    with open(path, 'r') as f:
        for line in f:
            num = int(line.split()[-1], 16)
            num = num - 0x20000000
            num = num // 1024
            data.append(num)

    print(len(data))
    plt.plot(data)
    plt.ylabel('free stack memory left [kB]')
    plt.xlabel('sample no.')
    plt.show()


if __name__ == '__main__':
    main()
