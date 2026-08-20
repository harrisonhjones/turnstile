import { Redirect, Route } from "react-router-dom";
import {
  IonApp,
  IonIcon,
  IonLabel,
  IonRouterOutlet,
  IonSpinner,
  IonTabBar,
  IonTabButton,
  IonTabs,
} from "@ionic/react";
import { IonReactRouter } from "@ionic/react-router";
import { documentText, key, time } from "ionicons/icons";
import { AuthProvider, useAuth } from "./auth";
import Audit from "./pages/Audit";
import Keys from "./pages/Keys";
import Login from "./pages/Login";
import Policy from "./pages/Policy";

// Shell renders the tabbed app once signed in, else the login screen.
function Shell() {
  const { signedIn, loading } = useAuth();

  if (loading) {
    return (
      <div className="ion-padding ion-text-center" style={{ marginTop: "20vh" }}>
        <IonSpinner />
      </div>
    );
  }
  if (!signedIn) return <Login />;

  return (
    <IonReactRouter basename="/ui">
      <IonTabs>
        <IonRouterOutlet>
          <Route exact path="/keys" component={Keys} />
          <Route exact path="/policy" component={Policy} />
          <Route exact path="/audit" component={Audit} />
          <Route exact path="/">
            <Redirect to="/keys" />
          </Route>
        </IonRouterOutlet>
        <IonTabBar slot="bottom">
          <IonTabButton tab="keys" href="/keys">
            <IonIcon icon={key} />
            <IonLabel>Keys</IonLabel>
          </IonTabButton>
          <IonTabButton tab="policy" href="/policy">
            <IonIcon icon={documentText} />
            <IonLabel>Policy</IonLabel>
          </IonTabButton>
          <IonTabButton tab="audit" href="/audit">
            <IonIcon icon={time} />
            <IonLabel>Audit</IonLabel>
          </IonTabButton>
        </IonTabBar>
      </IonTabs>
    </IonReactRouter>
  );
}

export default function App() {
  return (
    <IonApp>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </IonApp>
  );
}
