import click
import binascii


@click.command()
@click.argument('input', type=click.File('rt'))
@click.argument('output', type=click.File('wt'))
def main(input, output):
    a = input.read().strip()
    print(f'{len(a)} {a}')

    b = binascii.a2b_hex(a)
    c = map(int, b)
    d = list(c)
    output.write(str(d))

main()
