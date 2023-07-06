from matplotlib import pyplot as plt
import fire


def main(path, threshold=50):
    data = []
    last_line = []
    with open(path, 'r') as f:
        for i, line in enumerate(f):
            if "(*mut ()) 0x" not in line:
                last_line.append(line)
                continue
            try:
                num = int(line.split()[-1], 16)
            except Exception:
                print(f'Skipping "{line}"')
                continue

            num = num - 0x20000000
            num = num // 1024
            if num < 0 or num > 1*1024*1024:
                continue
            data.append(num)

            if num < threshold:
                print((i,len(data),num,last_line))
            last_line.clear()


    print(len(data))
    plt.plot(data)
    plt.ylabel('free stack memory left [kB]')
    plt.xlabel('sample no.')
    plt.show()


if __name__ == '__main__':
    fire.Fire()
