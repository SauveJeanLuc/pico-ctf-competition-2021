# Solve the quadratic equation ax**2 + bx + c = 0

# = q^2 - x q + n = 0
# import complex math module
import cmath

a = 1
b = 283448763112935396292672508494677342956387692709613190747337505254745038440112219196768813935476747610338768373312897468544362172877862811371116345292731982030202799279648808568611019652855145745874995725323535434244721756466664844450642633991884547297913224974132790120791402207195730139176850623910443635096
c = 19594979821655183104856721200876279688744199212596318791410700925214020940999368124753876379046101491755637328180352524777390418669210709696131801135729820817964419360433309338628094186567119917735965630612618443318361476838501333469511238156792898753876667912964148133223421606462036819614830830346046983259407147596111671725522875516790826213635619398696281968888325882416381776971733880221909903860599888903194248107358128483103962534467323374352040906477803568664482713174891860915973023918444553550090873773281086421418960484839799410173913761912529789181262819973734812402783319741028408456027454148088452256679

# calculate the discriminant
d = (b**2) - (4*a*c)

# find two solutions
sol1 = (-b-cmath.sqrt(d))/(2*a)
sol2 = (-b+cmath.sqrt(d))/(2*a)

print('The solution are {0} and {1}'.format(sol1,sol2))
